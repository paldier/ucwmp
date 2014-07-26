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

#include <libubox/utils.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "soap.h"
#include "rpc.h"
#include "object.h"
#include "../util.h"

static struct ubus_context *ubus_ctx;
static uint32_t cwmp_id;
static struct blob_buf b;

#define devinfo_fields(t, p) \
	_v(t, p, Manufacturer) \
	_v(t, p, ManufacturerOUI) \
	_v(t, p, ProductClass) \
	_v(t, p, SerialNumber) \

enum devinfo_fields {
	CWMP_ENUM(DEVINFO, devinfo_fields)
	__DEVINFO_MAX
};

static char *devinfo_values[__DEVINFO_MAX];

void server_load_info(const char *filename)
{
	static const struct blobmsg_policy devinfo_policy[__DEVINFO_MAX] = {
		CWMP_BLOBMSG_STRING(DEVINFO, devinfo_fields)
	};
	struct blob_attr *tb[__DEVINFO_MAX];
	static struct blob_buf b;
	int i;

	blob_buf_init(&b, 0);
	blobmsg_add_json_from_file(&b, filename);
	blobmsg_parse(devinfo_policy, __DEVINFO_MAX, tb, blob_data(b.head), blob_len(b.head));

	for (i = 0; i < __DEVINFO_MAX; i++) {
		if (!tb[i])
			continue;

		devinfo_values[i] = blobmsg_data(tb[i]);
	}
}

void cwmp_clear_pending_events(void)
{
	blob_buf_init(&b, 0);
	ubus_invoke(ubus_ctx, cwmp_id, "event_sent", b.head, NULL, NULL, 0);
}

void cwmp_add_device_id(node_t *node)
{
	struct xml_kv kv[] = {
		{ "Manufacturer", devinfo_values[DEVINFO_Manufacturer] },
		{ "OUI", devinfo_values[DEVINFO_ManufacturerOUI] },
		{ "ProductClass", devinfo_values[DEVINFO_ProductClass] },
		{ "SerialNumber", devinfo_values[DEVINFO_SerialNumber] },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(kv); i++)
		if (!kv[i].value)
			kv[i].value = "(unknown)";

	node = roxml_add_node(node, 0, ROXML_ELM_NODE, "DeviceId", NULL);
	xml_add_multi(node, ROXML_ELM_NODE, ARRAY_SIZE(kv), kv, NULL);
}

static void __constructor server_init(void)
{
	ubus_ctx = ubus_connect(NULL);
	ubus_lookup_id(ubus_ctx, "cwmp", &cwmp_id);

	cwmp_backend_init(ubus_ctx);
}

static void
cwmp_object_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blobmsg_policy policy = { "objects", BLOBMSG_TYPE_TABLE };
	struct blob_attr *data;
	bool *found = req->priv;

	blobmsg_parse(&policy, 1, &data, blob_data(msg), blob_len(msg));
	if (!data)
		return;

	*found = true;
	blob_buf_init(&b, 0);
	blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, NULL, blobmsg_data(data), blobmsg_data_len(data));
}

struct blob_attr *
cwmp_get_cache_instances(const char *path, struct blob_attr *data)
{
	bool found = false;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "path", path);
	blobmsg_add_field(&b, BLOBMSG_TYPE_ARRAY, "list",
			  blobmsg_data(data), blobmsg_data_len(data));
	ubus_invoke(ubus_ctx, cwmp_id, "object_list", b.head, cwmp_object_cb, &found, 0);

	if (!found)
		return NULL;

	return blob_data(b.head);
}

int cwmp_invoke(const char *cmd, struct blob_attr *data)
{
	return ubus_invoke(ubus_ctx, cwmp_id, cmd, data, NULL, NULL, 0);
}

int cwmp_invoke_noarg(const char *cmd)
{
	blob_buf_init(&b, 0);
	return cwmp_invoke(cmd, b.head);
}
