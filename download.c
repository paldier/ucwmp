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
#include <libubox/uloop.h>
#include "state.h"

static LIST_HEAD(downloads);

enum download_state {
	DL_STATE_NEW,
	DL_STATE_READY,
};

struct cwmp_download {
	struct list_head list;
	struct uloop_timeout timeout;

	const char *ckey;
	const char *type;
	const char *url;
	const char *username;
	const char *password;

	uint32_t start;

	enum download_state state;
};

const struct blobmsg_policy transfer_policy[__CWMP_DL_MAX] = {
	[CWMP_DL_CKEY] = { "command_key", BLOBMSG_TYPE_STRING },
	[CWMP_DL_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[CWMP_DL_URL] = { "url", BLOBMSG_TYPE_STRING },
	[CWMP_DL_USERNAME] = { "username", BLOBMSG_TYPE_STRING },
	[CWMP_DL_PASSWORD] = { "password", BLOBMSG_TYPE_STRING },
	[CWMP_DL_STATE] = { "state", BLOBMSG_TYPE_INT32 },
	[CWMP_DL_START] = { "start", BLOBMSG_TYPE_INT32 },
};

static const char *get_string(struct blob_attr *data)
{
	if (!data)
		return NULL;

	return blobmsg_data(data);
}

void cwmp_download_add(struct blob_attr *attr, bool internal)
{
	struct blob_attr *tb[__CWMP_DL_MAX];
	struct cwmp_download *dl;
	struct blob_attr *data, *cur;

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
		dl->state = blobmsg_get_u32(cur);

	if (!dl->url || !dl->type)
		goto error;

	fprintf(stderr, "Add download, type=%s url=%s\n", dl->type, dl->url);
	list_add(&dl->list, &downloads);
	return;

error:
	free(dl);
}

static void cwmp_download_delete(struct cwmp_download *dl)
{
	uloop_timeout_cancel(&dl->timeout);
	list_del(&dl->list);
	free(dl);
}

static void cwmp_download_ready(struct cwmp_download *dl)
{
	uloop_timeout_cancel(&dl->timeout);
	/* start */
}

static void cwmp_download_timer(struct uloop_timeout *timeout)
{
	cwmp_download_check_pending();
}

void cwmp_download_check_pending(void)
{
	struct cwmp_download *dl, *tmp;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	list_for_each_entry_safe(dl, tmp, &downloads, list) {
		int64_t offset = (int64_t) tv.tv_sec - (int64_t) dl->start;

		if (offset < 0) {
			dl->timeout.cb = cwmp_download_timer;
			uloop_timeout_set(&dl->timeout, -(offset + 1) * 1000);
			continue;
		}

		if (offset > 3600) {
			cwmp_download_delete(dl);
			continue;
		}

		cwmp_download_ready(dl);
	}
}
