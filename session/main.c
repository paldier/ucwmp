/*
 * cwmpd - CPE WAN Management Protocol daemon
 * Copyright (C) 2014 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdarg.h>

#include <libubox/uloop.h>
#include <libubox/uclient.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/ustream-ssl.h>
#include <json-c/json.h>
#include <dlfcn.h>

#include "soap.h"
#include "rpc.h"
#include "attr.h"
#include "backend.h"

bool session_init = true;

static int debug_level = 0;
static char *buf;
static int buf_len, buf_ofs;

static struct uclient *uc;
static struct ustream_ssl_ctx *ssl_ctx;
static const struct ustream_ssl_ops *ssl_ops;
static void *dlh;

static char *cur_request;
static char *url, *username, *password, *local_port = "8080";

static LIST_HEAD(cookies);
struct blob_buf events;

struct cookie {
	struct list_head list;
	const char *key;
	const char *value;
};

static void cwmp_process_cookies(struct uclient *cl)
{
	static const struct blobmsg_policy cookie = {
		.name = "set-cookie",
		.type = BLOBMSG_TYPE_STRING
	};
	struct blob_attr *attr;
	struct cookie *new, *cur, *tmp;
	char *data, *sep;
	int len;

	blobmsg_parse(&cookie, 1, &attr, blob_data(cl->meta), blob_len(cl->meta));
	if (!attr)
		return;

	data = blobmsg_data(attr);
	len = strlen(data);
	sep = strchr(data, ';');
	if (sep)
		len = sep - data;

	new = calloc_a(sizeof(*new), &data, len + 1);
	new->key = strncpy(data, blobmsg_data(attr), len);
	sep = strchr(new->key, '=');
	*sep = 0;
	new->value = sep + 1;

	list_for_each_entry_safe(cur, tmp, &cookies, list) {
		if (strcmp(cur->key, new->key) != 0)
			continue;

		list_del(&cur->list);
		free(cur);
	}

	list_add_tail(&new->list, &cookies);
}

static void cwmp_add_cookies(struct uclient *cl)
{
	struct cookie *cur;
	char *attr = NULL;
	int cur_len = 0;

	list_for_each_entry(cur, &cookies, list) {
		int len = strlen(cur->key) + strlen(cur->value) + 1;
		int ofs = cur_len;

		cur_len += len;
		if (ofs)
			cur_len += 2;

		attr = realloc(attr, cur_len + 1);
		sprintf(attr + ofs, "%s%s=%s", ofs ? "; " : "", cur->key, cur->value);
	}

	if (!attr)
		return;

	uclient_http_set_header(cl, "Cookie", attr);
	free(attr);
}

void cwmp_debug(int level, const char *system, const char *fmt, ...)
{
	va_list ap;

	if (level > debug_level)
		return;

	va_start(ap, fmt);
	fprintf(stderr, "DEBUG[%s]: ", system);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void cwmp_dump_message(const char *msg, const char *data)
{
	const char *sep = "------------------------------------------------------------------------------------\n";
	char *new_str = NULL;

	if (!debug_level)
		return;

	if (debug_level > 1) {
		node_t *node;

		node = roxml_load_buf((char *) data);
		if (node) {
			roxml_commit_changes(node, NULL, &new_str, 1);
			if (new_str)
				data = new_str;
			roxml_close(node);
		}
	}

	fprintf(stderr, "%s\n%s%s%s\n", msg, sep, data, sep);

	if (debug_level > 1)
		roxml_release(new_str);
}

static void __cwmp_send_request(struct uloop_timeout *t)
{
	int len = 0;
	cwmp_dump_message("Send CPE data", cur_request);

	if (uclient_connect(uc)) {
		if (debug_level)
			perror("Failed to connect to CPE");
		return;
	}

	uclient_http_reset_headers(uc);
	uclient_http_set_request_type(uc, "POST");
	cwmp_add_cookies(uc);

	if (cur_request)
		len = strlen(cur_request);

	if (len > 0) {
		uclient_http_set_header(uc, "SOAPAction", "");
		uclient_http_set_header(uc, "Content-Type", "text/xml");
		uclient_write(uc, cur_request, len);
	}

	uclient_request(uc);

	buf_ofs = 0;
}

static void cwmp_send_request(void)
{
	static struct uloop_timeout t = {
		.cb = __cwmp_send_request,
	};

	uloop_timeout_set(&t, 1);
}


static void cwmp_free_request(void)
{
	roxml_release(cur_request);
	cur_request = NULL;
}

static void cwmp_data_read(struct uclient *cl)
{
	int len;

	do {
		if (buf_len < buf_ofs + 256) {
			buf_len += 256;
			buf = realloc(buf, buf_len);
		}

		len = uclient_read(cl, buf + buf_ofs, buf_len - buf_ofs);
		if (len > 0)
			buf_ofs += len;
	} while (len > 0);
}

static void cwmp_data_eof(struct uclient *cl)
{
	static int retries, auth_retries;
	char *msg = buf;

	if (buf)
		buf[buf_ofs] = 0;

	if (retries < 7 && uclient_http_redirect(cl)) {
		retries++;
		return;
	}

	retries = 0;
	switch (cl->status_code) {
	case 204:
		msg = NULL;
	case 200:
		auth_retries = 0;
		cwmp_process_cookies(cl);
		cwmp_free_request();
		cwmp_dump_message("Received ACS data", buf);
		cur_request = soap_handle_msg(msg);
		cwmp_send_request();
		break;
	case 401:
		if (auth_retries++ < 2) {
			if (debug_level)
				fprintf(stderr, "Retry after authenticating\n");
			cwmp_send_request();
			break;
		}
		/* fall through */
	default:
		fprintf(stderr, "Got HTTP error %d\n", cl->status_code);
		uloop_end();
		break;
	}
}

static void cwmp_error(struct uclient *cl, int code)
{
	fprintf(stderr, "Got uclient error %d\n", code);
	uloop_end();
}

static void init_ustream_ssl()
{
	dlh = dlopen("libustream-ssl.so", RTLD_LAZY | RTLD_LOCAL);
	if (!dlh)
		return;

	ssl_ops = dlsym(dlh, "ustream_ssl_ops");
	if (!ssl_ops)
		return;

	ssl_ctx = ssl_ops->context_new(false);
}

static void deinit_ustream_ssl()
{
	if (ssl_ctx)
		ssl_ops->context_free(ssl_ctx);
	if (dlh)
		dlclose(dlh);
}

static int cwmp_connect(void)
{
	static struct uclient_cb cwmp_cb = {
		.data_read = cwmp_data_read,
		.data_eof = cwmp_data_eof,
		.error = cwmp_error,
	};
	char *auth_str;
	int err;

	if (uc)
		return -1;

	if (!username && !password)
		auth_str = NULL;
	else if (!password)
		auth_str = username;
	else {
		auth_str = alloca(strlen(username) + strlen(password) + 2);
		sprintf(auth_str, "%s:%s", username, password);
	}

	if (debug_level)
		fprintf(stderr, "Connecting to %s\n", url);

	uc = uclient_new(url, auth_str, &cwmp_cb);
	uclient_http_set_ssl_ctx(uc, ssl_ops, ssl_ctx, 0);
	err = uclient_connect(uc);
	if (err) {
		if (debug_level)
			fprintf(stderr, "Failed to connect to CPE: %s: %s\n",
				uclient_strerror(err), strerror(errno));
		return -1;
	}
	return 0;
}

static int usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [options] <url>\n"
		"Options:\n"
		"	-e <json>:      Load events from JSON string\n"
		"	-a <file>:	Set attribute cache filename to <file>\n"
		"	-d <level>:     Set debug level\n"
		"	-u <username>:  Set ACS username\n"
		"	-p <password>:  Set ACS password\n"
		"	-P <port>:	Set local connection port\n"
		"\n", progname);
	return 1;
}

static int load_events(const char *data)
{
	json_object *obj = json_tokener_parse(data);

	if (is_error(obj)) {
		fprintf(stderr, "Could not parse event data\n");
		return -1;
	}

	if (json_object_get_type(obj) != json_type_array) {
		json_object_put(obj);
		fprintf(stderr, "JSON event data must be an array\n");
		return -1;
	}

	blob_buf_init(&events, 0);
	blobmsg_add_json_element(&events, "events", obj);
	json_object_put(obj);

	return 0;
}

int main(int argc, char **argv)
{
	const char *progname = argv[0];
	char local_addr[INET6_ADDRSTRLEN];
	int ch;

	uloop_init();

	while ((ch = getopt(argc, argv, "a:d:e:u:p:P:")) != -1) {
		switch (ch) {
		case 'a':
			attr_cache_file = optarg;
			break;
		case 'd':
			debug_level = atoi(optarg);
			break;
		case 'e':
			if (load_events(optarg))
				return 1;
			break;
		case 'u':
			username = optarg;
			break;
		case 'p':
			password = strdup(optarg);
			memset(optarg, 0, strlen(optarg));
			break;
		case 'P':
			local_port = optarg;
			break;
		default:
			return usage(progname);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 1)
		return usage(progname);

	url = argv[0];
	session_init = false;
	init_ustream_ssl();

	if (cwmp_connect())
		return 1;

	uclient_get_addr(local_addr, NULL, &uc->local_addr);
	server_update_local_addr(local_addr, local_port);

	cur_request = soap_init_session();
	cwmp_send_request();

	uloop_run();
	uloop_done();
	backend_deinit();
	deinit_ustream_ssl();
	return 0;
}
