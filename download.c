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
#define _GNU_SOURCE
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#include <libubox/uloop.h>
#include <libubox/uclient-utils.h>

#include "state.h"

static LIST_HEAD(downloads);

enum download_state {
	DL_STATE_NEW,
	DL_STATE_READY,
	DL_STATE_DOWNLOAD,
	DL_STATE_APPLY,
};

struct cwmp_download {
	struct list_head list;
	struct uloop_timeout timeout;

	const char *ckey;
	const char *type;
	const char *url;
	const char *username;
	const char *password;
	const char *filename;

	uint32_t start;

	enum download_state state;
};

static struct cwmp_download *cur_download;
static char *cur_dl_file, *cur_dl_path;
static struct uloop_process dl_proc;

const struct blobmsg_policy transfer_policy[__CWMP_DL_MAX] = {
	[CWMP_DL_CKEY] = { "command_key", BLOBMSG_TYPE_STRING },
	[CWMP_DL_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[CWMP_DL_URL] = { "url", BLOBMSG_TYPE_STRING },
	[CWMP_DL_USERNAME] = { "username", BLOBMSG_TYPE_STRING },
	[CWMP_DL_PASSWORD] = { "password", BLOBMSG_TYPE_STRING },
	[CWMP_DL_STATE] = { "state", BLOBMSG_TYPE_INT32 },
	[CWMP_DL_START] = { "start", BLOBMSG_TYPE_INT32 },
	[CWMP_DL_FILENAME] = { "filename", BLOBMSG_TYPE_STRING },
};

static const char *get_string(struct blob_attr *data)
{
	if (!data)
		return NULL;

	return blobmsg_data(data);
}

static void add_string(struct blob_buf *buf, int field, const char *val)
{
	if (!val)
		return;

	blobmsg_add_string(buf, transfer_policy[field].name, val);
}

void cwmp_state_get_downloads(struct blob_buf *buf)
{
	struct cwmp_download *dl;
	void *c;

	list_for_each_entry(dl, &downloads, list) {
		c = blobmsg_open_table(buf, NULL);
		add_string(buf, CWMP_DL_CKEY, dl->ckey);
		add_string(buf, CWMP_DL_TYPE, dl->type);
		add_string(buf, CWMP_DL_URL, dl->url);
		add_string(buf, CWMP_DL_USERNAME, dl->username);
		add_string(buf, CWMP_DL_PASSWORD, dl->password);
		add_string(buf, CWMP_DL_FILENAME, dl->filename);
		blobmsg_add_u32(buf, transfer_policy[CWMP_DL_STATE].name, dl->state);
		blobmsg_add_u32(buf, transfer_policy[CWMP_DL_START].name, dl->start);
		blobmsg_close_table(buf, c);
	}
}

void cwmp_download_add(struct blob_attr *attr, bool internal)
{
	struct blob_attr *tb[__CWMP_DL_MAX];
	struct cwmp_download *dl;
	struct blob_attr *data, *cur;
	int state = DL_STATE_NEW;

	dl = calloc_a(sizeof(*dl), &data, blob_pad_len(attr));
	memcpy(data, attr, blob_pad_len(attr));

	blobmsg_parse(transfer_policy, __CWMP_DL_MAX, tb,
		      blobmsg_data(data), blobmsg_data_len(data));

	dl->ckey = get_string(tb[CWMP_DL_CKEY]);
	dl->type = get_string(tb[CWMP_DL_TYPE]);
	dl->url = get_string(tb[CWMP_DL_URL]);
	dl->username = get_string(tb[CWMP_DL_USERNAME]);
	dl->password = get_string(tb[CWMP_DL_PASSWORD]);

	cur = tb[CWMP_DL_START];
	if (!cur)
		goto error;

	dl->start = blobmsg_get_u32(cur);

	if (internal && (cur = tb[CWMP_DL_STATE]))
		state = blobmsg_get_u32(cur);

	switch (state) {
	case DL_STATE_DOWNLOAD:
		dl->state = DL_STATE_READY;
		break;
	case DL_STATE_APPLY:
		if (!cur_download)
			cur_download = dl;
	case DL_STATE_NEW:
	case DL_STATE_READY:
		dl->state = state;
		break;
	default:
		break;
	}

	if (!dl->url || !dl->type)
		goto error;

	fprintf(stderr, "Add download, type=%s url=%s\n", dl->type, dl->url);
	list_add_tail(&dl->list, &downloads);
	if (!internal)
		cwmp_save_cache(false);

	return;

error:
	free(dl);
}

static void cwmp_download_delete(struct cwmp_download *dl)
{
	if (dl == cur_download)
		return;

	uloop_timeout_cancel(&dl->timeout);
	list_del(&dl->list);
	free(dl);

	cwmp_save_cache(false);
}

static void cwmp_download_reset(void)
{
	if (dl_proc.pending) {
		kill(dl_proc.pid, SIGKILL);
		uloop_process_delete(&dl_proc);
	}

	cur_download = NULL;

	free(cur_dl_file);
	cur_dl_file = NULL;

	free(cur_dl_path);
	cur_dl_path = NULL;
}

static void __cwmp_download_done(struct cwmp_download *dl, int code)
{
	static struct blob_buf b;

	if (dl == cur_download)
		cwmp_download_reset();

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "type", "TransferComplete");
	blobmsg_add_u32(&b, "error", code);

	cwmp_flag_event("M Download", dl->ckey, b.head);
	cwmp_download_delete(dl);
}

void cwmp_download_done(struct blob_attr *attr)
{
	struct blob_attr *tb[__CWMP_DL_MAX];
	struct cwmp_download *dl, *tmp;
	const char *url;

	blobmsg_parse(transfer_policy, __CWMP_DL_MAX, tb,
		      blobmsg_data(attr), blobmsg_data_len(attr));

	if (!tb[CWMP_DL_URL])
		return;

	url = blobmsg_data(tb[CWMP_DL_URL]);

	list_for_each_entry_safe(dl, tmp, &downloads, list) {
		if (dl->state != DL_STATE_APPLY)
			continue;

		if (strcmp(dl->url, url) != 0)
			continue;

		__cwmp_download_done(dl, 0);
	}
}

static void cwmp_download_apply_cb(struct uloop_process *p, int ret)
{
}

static void cwmp_download_apply(struct cwmp_download *dl)
{
	dl->state = DL_STATE_APPLY;
	cwmp_save_cache(true);

	dl_proc.cb = cwmp_download_apply_cb;

	dl_proc.pid = fork();
	switch (dl_proc.pid) {
	case 0:
		cwmp_download_apply_exec(cur_dl_path, dl->type, cur_dl_file, dl->url);
		break;
	case -1:
		__cwmp_download_done(dl, 9002);
		break;
	default:
		uloop_process_add(&dl_proc);
		break;
	}
}

static void cwmp_download_cb(struct uloop_process *p, int ret)
{
	if (!cur_download)
		return;

	if (ret) {
		__cwmp_download_done(cur_download, 9015);
		return;
	}

	cwmp_download_apply(cur_download);
}

static void cwmp_download_run(void)
{
	struct cwmp_download *dl = cur_download;
	const char *argv[] = {
		"uclient-fetch",
		"-O",
		cur_dl_path,
		"--user",
		dl->username ? dl->username : "",
		"--password",
		dl->password ? dl->password : "",
		dl->url,
		NULL
	};

	int i;

	printf("exec:");
	for (i = 0; argv[i]; i++)
		printf(" %s", argv[i]);
	puts("");

	execvp(argv[0], (char **) argv);
	exit(255);
}

static void cwmp_download_start(struct cwmp_download *dl)
{
	const char *cur_name;

	cwmp_download_reset();

	cur_download = dl;
	dl->state = DL_STATE_DOWNLOAD;

	if (dl->filename)
		cur_dl_file = strdup(dl->filename);
	else
		cur_dl_file = uclient_get_url_filename(dl->url, "file");

	cur_name = strrchr(cur_dl_file, '/');
	cur_name = cur_name ? cur_name + 1 : cur_dl_file;

	asprintf(&cur_dl_path, "/tmp/download.%d.%s", dl->start, cur_name);
	dl_proc.cb = cwmp_download_cb;

	dl_proc.pid = fork();
	switch (dl_proc.pid) {
	case 0:
		cwmp_download_run();
		break;
	case -1:
		__cwmp_download_done(dl, 9002);
		break;
	default:
		uloop_process_add(&dl_proc);
		break;
	}
}

static void cwmp_download_timer(struct uloop_timeout *timeout)
{
	cwmp_download_check_pending(false);
}

void cwmp_download_check_pending(bool session_complete)
{
	struct cwmp_download *dl, *tmp;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	list_for_each_entry_safe(dl, tmp, &downloads, list) {
		int64_t offset = (int64_t) tv.tv_sec - (int64_t) dl->start;

		if (dl->state == DL_STATE_NEW) {
			if (!session_complete)
				continue;
			else
				dl->state = DL_STATE_READY;
		}

		if (offset < 0) {
			dl->timeout.cb = cwmp_download_timer;
			uloop_timeout_set(&dl->timeout, -(offset + 1) * 1000);
			continue;
		}

		if (offset > 3600) {
			cwmp_download_delete(dl);
			continue;
		}

		uloop_timeout_cancel(&dl->timeout);
		if (cur_download)
			continue;

		cwmp_download_start(dl);
	}
}
