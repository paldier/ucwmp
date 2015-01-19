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
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#include <libubox/utils.h>
#include <libubox/blobmsg.h>
#include <libubox/uclient.h>
#include <libubox/uclient-utils.h>

#include <libubus.h>

#define __digest_fields_quoted \
	__digest_field(username) \
	__digest_field(realm) \
	__digest_field(nonce) \
	__digest_field(uri) \
	__digest_field(response) \
	__digest_field(cnonce) \
	__digest_field(algorithm)

#define __digest_fields_unquoted \
	__digest_field(qop) \
	__digest_field(nc)

#define __digest_fields \
	__digest_fields_quoted \
	__digest_fields_unquoted

enum digest_fields {
#define __digest_field(name) DIGEST_##name,
	__digest_fields
#undef __digest_field
	__DIGEST_FIELDS
};

static const char * const digest_field_names[__DIGEST_FIELDS] = {
#define __digest_field(name) [DIGEST_##name] = #name,
	__digest_fields
#undef __digest_field
};

static const unsigned int digest_quoted_mask =
#define __digest_field(name) (1 << DIGEST_##name) |
	__digest_fields_quoted
#undef __digest_field
	0;

static struct blob_buf b;

static int digest_find_idx(const char *str)
{
	int i;

	for (i = 0; i < __DIGEST_FIELDS; i++) {
		if (!strcmp(digest_field_names[i], str))
			return i;
	}

	return -1;
}

static char *digest_unquote_sep(char **str)
{
	char *cur = *str + 1;
	char *start = cur;
	char *out;

	if (**str != '"')
		return NULL;

	out = cur;
	while (1) {
		if (!*cur)
			return NULL;

		if (*cur == '"') {
			cur++;
			break;
		}

		if (*cur == '\\')
			cur++;

		*(out++) = *(cur++);
	}

	if (*cur == ',')
		cur++;

	*out = 0;
	*str = cur;

	return start;
}

static bool digest_parse_fields(char *str, char **tb)
{
	char *cur;
	int idx;

	memset(tb, 0, __DIGEST_FIELDS * sizeof(tb));

	while (*str) {
		while (isspace(*str))
			str++;

		cur = strsep(&str, "=");
		idx = digest_find_idx(cur);
		if (idx < 0)
			return false;

		if (digest_quoted_mask & (1 << idx))
			cur = digest_unquote_sep(&str);
		else
			cur = strsep(&str, ",");

		if (!cur)
			return false;

		tb[idx] = cur;
	}

	for (idx = 0; idx < __DIGEST_FIELDS; idx++)
		if (!tb[idx])
			return false;

	return true;
}

static void fill_connection_request(void)
{
	char *auth = getenv("HTTP_AUTHORIZATION");
	const char *method = getenv("REQUEST_METHOD");
	const char *uri = getenv("REQUEST_URI");

	char *fields[__DIGEST_FIELDS];
	char *type;
	int i;

	if (!auth || !uri || !method)
		return;

	type = strsep(&auth, " ");
	if (!type)
		return;

	if (strcasecmp(type, "digest") != 0)
		return;

	if (!digest_parse_fields(auth, fields))
		return;

	if (strcmp(uri, fields[DIGEST_uri]) != 0)
		return;

	for (i = 0; i < __DIGEST_FIELDS; i++) {
		if (!fields[i])
			continue;

		blobmsg_add_string(&b, digest_field_names[i], fields[i]);
	}
}

enum {
	REQ_OK,
	REQ_REALM,
	REQ_NONCE,
	__REQ_MAX
};

static bool data_ok = false;

static void cwmpd_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	static const struct blobmsg_policy policy[__REQ_MAX] = {
		[REQ_OK] = { "ok", BLOBMSG_TYPE_BOOL },
		[REQ_REALM] = { "realm", BLOBMSG_TYPE_STRING },
		[REQ_NONCE] = { "nonce", BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[__REQ_MAX];
	const char *status;

	blobmsg_parse(policy, __REQ_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[REQ_OK] || !tb[REQ_REALM] || !tb[REQ_NONCE])
		return;

	data_ok = true;
	if (!blobmsg_get_bool(tb[REQ_OK]))
		status = "401 Unauthorized";
	else
		status = "200 OK";

	printf("Status: %s\n", status);
	printf("WWW-Authenticate: Digest qop=\"auth\", realm=\"%s\", nonce=\"%s\"\n",
		(char *) blobmsg_data(tb[REQ_REALM]),
		(char *) blobmsg_data(tb[REQ_NONCE]));
	printf("Content-Length: 0\n\n");
}

static void http_validate(struct ubus_context *ctx)
{
	uint32_t cwmp_id;

	blob_buf_init(&b, 0);
	fill_connection_request();

	ubus_lookup_id(ctx, "cwmp", &cwmp_id);
	ubus_invoke(ctx, cwmp_id, "connection_request", b.head, cwmpd_cb, NULL, 0);

	if (!data_ok)
		printf("Status: 500 Internal Server Error\n\n");
}

int main(int argc, char **argv)
{
	struct ubus_context *ctx;

	ctx = ubus_connect(NULL);
	http_validate(ctx);
	fflush(stdout);

	return 0;
}
