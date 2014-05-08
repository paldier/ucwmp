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
#include "state.h"

static LIST_HEAD(downloads);

struct cwmp_download {
	struct list_head list;
	const char *ckey;
	const char *type;
	const char *url;
	const char *username;
	const char *password;
};

const struct blobmsg_policy transfer_policy[__CWMP_DL_MAX] = {
	[CWMP_DL_CKEY] = { "command_key", BLOBMSG_TYPE_STRING },
	[CWMP_DL_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[CWMP_DL_URL] = { "url", BLOBMSG_TYPE_STRING },
	[CWMP_DL_USERNAME] = { "username", BLOBMSG_TYPE_STRING },
	[CWMP_DL_PASSWORD] = { "password", BLOBMSG_TYPE_STRING },
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
	struct blob_attr *data;

	dl = calloc_a(sizeof(*dl), &data, blob_pad_len(attr));
	memcpy(data, attr, blob_pad_len(attr));

	blobmsg_parse(transfer_policy, __CWMP_DL_MAX, tb,
		      blobmsg_data(data), blobmsg_data_len(data));

	dl->ckey = get_string(tb[CWMP_DL_CKEY]);
	dl->type = get_string(tb[CWMP_DL_TYPE]);
	dl->url = get_string(tb[CWMP_DL_URL]);
	dl->username = get_string(tb[CWMP_DL_USERNAME]);
	dl->password = get_string(tb[CWMP_DL_PASSWORD]);

	if (!dl->url || !dl->type) {
		free(dl);
		return;
	}

	fprintf(stderr, "Add download, type=%s url=%s\n", dl->type, dl->url);
	list_add(&dl->list, &downloads);
}