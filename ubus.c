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
#include <time.h>

#include <libubox/uclient.h>
#include <libubox/uclient-utils.h>
#include <libubus.h>

#include "state.h"

static struct ubus_context *ctx;
static struct blob_buf b;
static char auth_md5[33];

static const char * const auth_realm = "ucwmp";

enum {
	CONN_REQ_USERNAME,
	CONN_REQ_REALM,
	CONN_REQ_NONCE,
	CONN_REQ_URI,
	CONN_REQ_RESPONSE,
	CONN_REQ_CNONCE,
	CONN_REQ_NC,
	__CONN_REQ_MAX,
};

static const struct blobmsg_policy conn_req_policy[__CONN_REQ_MAX] = {
	[CONN_REQ_USERNAME] = { "username", BLOBMSG_TYPE_STRING },
	[CONN_REQ_REALM] = { "realm", BLOBMSG_TYPE_STRING },
	[CONN_REQ_NONCE] = { "nonce", BLOBMSG_TYPE_STRING },
	[CONN_REQ_URI] = { "uri", BLOBMSG_TYPE_STRING },
	[CONN_REQ_RESPONSE] = { "response", BLOBMSG_TYPE_STRING },
	[CONN_REQ_CNONCE] = { "cnonce", BLOBMSG_TYPE_STRING },
	[CONN_REQ_NC] = { "nc", BLOBMSG_TYPE_STRING },
};

static void conn_req_challenge(void)
{
	time_t cur = time(NULL);
	char nonce[9];

	snprintf(nonce, sizeof(nonce), "%08x", (uint32_t) cur);
	blobmsg_add_string(&b, "nonce", nonce);
	blobmsg_add_string(&b, "realm", auth_realm);
}

static bool conn_req_check_digest(struct blob_attr **tb)
{
	struct http_digest_data data = {
		.uri = blobmsg_data(tb[CONN_REQ_URI]),
		.method = "GET",
		.auth_hash = auth_md5,
		.qop = "auth",
		.nc = blobmsg_data(tb[CONN_REQ_NC]),
		.nonce = blobmsg_data(tb[CONN_REQ_NONCE]),
		.cnonce = blobmsg_data(tb[CONN_REQ_CNONCE]),
	};
	char md5[33];

	http_digest_calculate_response(md5, &data);

	return !strcmp(blobmsg_data(tb[CONN_REQ_RESPONSE]), md5);
}

static bool conn_req_validate(struct blob_attr **tb)
{
	const char *password = "";
	int i;

	if (!config.local_username)
		return true;

	if (config.local_password)
		password = config.local_password;

	http_digest_calculate_auth_hash(auth_md5, config.local_username,
					auth_realm, password);

	for (i = 0; i < __CONN_REQ_MAX; i++) {
		if (!tb[i])
			return false;
	}

	return conn_req_check_digest(tb);
}

static int
cwmp_connection_request(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__CONN_REQ_MAX];
	bool ok;

	blob_buf_init(&b, 0);

	blobmsg_parse(conn_req_policy, __CONN_REQ_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));

	ok = conn_req_validate(tb);
	conn_req_challenge();
	blobmsg_add_u8(&b, "ok", ok);

	if (ok)
		cwmp_flag_event("6 CONNECTION REQUEST", NULL, NULL);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int
cwmp_event_sent(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	cwmp_clear_pending_events();
	return 0;
}

static const struct blobmsg_policy event_policy[] = {
	{ .name = "event", .type = BLOBMSG_TYPE_STRING },
	{ .name = "commandkey", .type = BLOBMSG_TYPE_STRING },
	{ .name = "data", .type = BLOBMSG_TYPE_TABLE },
};

static int
cwmp_event_add(struct ubus_context *ctx, struct ubus_object *obj,
	       struct ubus_request_data *req, const char *method,
	       struct blob_attr *msg)
{
	struct blob_attr *tb[3];
	const char *id, *ckey = NULL;

	blobmsg_parse(event_policy, ARRAY_SIZE(event_policy), tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (!tb[0])
		return UBUS_STATUS_INVALID_ARGUMENT;

	id = blobmsg_data(tb[0]);
	if (tb[1])
		ckey = blobmsg_data(tb[1]);

	cwmp_flag_event(id, ckey, tb[2]);
	return 0;
}

static int
cwmp_session_completed(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	session_success = true;
	return 0;
}

static int
cwmp_download_req(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{

	cwmp_download_add(msg, false);

	return 0;
}

static int
cwmp_download_done_req(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{

	cwmp_download_done(msg);

	return 0;
}

static int
cwmp_factory_reset(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	pending_cmd = CMD_FACTORY_RESET;
	return 0;
}

static int
cwmp_reboot(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg)
{
	pending_cmd = CMD_REBOOT;
	return 0;
}

static int
cwmp_reload(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg)
{
	cwmp_load_config();
	return 0;
}

enum {
	OBJECT_PATH,
	OBJECT_LIST,
	__OBJECT_MAX,
};

static const struct blobmsg_policy obj_policy[] = {
	[OBJECT_PATH] = { "path", BLOBMSG_TYPE_STRING },
	[OBJECT_LIST] = { "list", BLOBMSG_TYPE_ARRAY },
};

static int
cwmp_object_list(struct ubus_context *ctx, struct ubus_object *obj,
		 struct ubus_request_data *req, const char *method,
		 struct blob_attr *msg)
{
	struct blob_attr *tb[__OBJECT_MAX];
	struct blob_attr *list;
	const char *path;

	blobmsg_parse(obj_policy, __OBJECT_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (!tb[OBJECT_PATH] || !tb[OBJECT_LIST])
		return UBUS_STATUS_INVALID_ARGUMENT;

	path = blobmsg_get_string(tb[OBJECT_PATH]);
	list = tb[OBJECT_LIST];

	list = cwmp_object_cache_get(path, list);

	blob_buf_init(&b, 0);
	blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "objects",
			  blobmsg_data(list), blobmsg_data_len(list));
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static struct ubus_method cwmp_methods[] = {
	UBUS_METHOD_NOARG("connection_request", cwmp_connection_request),
	UBUS_METHOD_NOARG("event_sent", cwmp_event_sent),
	UBUS_METHOD("event_add", cwmp_event_add, event_policy),

	UBUS_METHOD("download_add", cwmp_download_req, transfer_policy),
	UBUS_METHOD_MASK("download_done", cwmp_download_done_req, transfer_policy,
			 (1 << CWMP_DL_URL)),

	UBUS_METHOD("object_list", cwmp_object_list, obj_policy),
	UBUS_METHOD_NOARG("factory_reset", cwmp_factory_reset),
	UBUS_METHOD_NOARG("reboot", cwmp_reboot),
	UBUS_METHOD_NOARG("reload", cwmp_reload),

	UBUS_METHOD_NOARG("session_completed", cwmp_session_completed),
};

static struct ubus_object_type cwmp_object_type =
	UBUS_OBJECT_TYPE("cwmp", cwmp_methods);

static struct ubus_object cwmp_object = {
	.name = "cwmp",
	.type = &cwmp_object_type,
	.methods = cwmp_methods,
	.n_methods = ARRAY_SIZE(cwmp_methods),
};

void cwmp_ubus_command(struct blob_attr *data)
{
	struct blobmsg_policy policy[2] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *tb[2];
	const char *name;

	blobmsg_parse_array(policy, ARRAY_SIZE(policy), tb, blobmsg_data(data), blobmsg_data_len(data));
	if (!tb[0] || !tb[1])
		return;

	name = blobmsg_data(tb[0]);

	if (!strcmp(name, "download_done"))
		cwmp_download_done_req(ctx, &cwmp_object, NULL, NULL, tb[1]);
}

int cwmp_ubus_register(void)
{
	ctx = ubus_connect(NULL);
	if (!ctx)
		return -1;

	if (ubus_add_object(ctx, &cwmp_object))
		return -1;

	ubus_add_uloop(ctx);
	return 0;
}
