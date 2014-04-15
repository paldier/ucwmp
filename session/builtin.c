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
static int conn_req_port;

enum {
	MGMT_ATTR_URL,
	MGMT_ATTR_USERNAME,
	MGMT_ATTR_PASSWORD,
	MGMT_ATTR_PERIODIC_ENABLED,
	MGMT_ATTR_PERIODIC_INTERVAL,
	MGMT_ATTR_CONNECTION_REQUEST_URL,
	MGMT_ATTR_CONNECTION_REQUEST_USERNAME,
	MGMT_ATTR_CONNECTION_REQUEST_PASSWORD,
	__MGMT_ATTR_MAX,
};

static char *server_values[__MGMT_ATTR_MAX];
static const char * const server_params[__MGMT_ATTR_MAX] = {
	[MGMT_ATTR_URL] = "URL",
	[MGMT_ATTR_USERNAME] = "Username",
	[MGMT_ATTR_PASSWORD] = "Password",
	[MGMT_ATTR_PERIODIC_ENABLED] = "PeriodicInformEnable",
	[MGMT_ATTR_PERIODIC_INTERVAL] = "PeriodicInformInterval",
	[MGMT_ATTR_CONNECTION_REQUEST_URL] = "ConnectionRequestURL",
	[MGMT_ATTR_CONNECTION_REQUEST_USERNAME] = "ConnectionRequestUsername",
	[MGMT_ATTR_CONNECTION_REQUEST_PASSWORD] = "ConnectionRequestPassword",
};

static const char * const server_types[__MGMT_ATTR_MAX] = {
	[MGMT_ATTR_URL] = "string",
	[MGMT_ATTR_USERNAME] = "string",
	[MGMT_ATTR_PASSWORD] = "string",
	[MGMT_ATTR_PERIODIC_ENABLED] = "boolean",
	[MGMT_ATTR_PERIODIC_INTERVAL] = "unsignedInt",
	[MGMT_ATTR_CONNECTION_REQUEST_URL] = "string",
	[MGMT_ATTR_CONNECTION_REQUEST_USERNAME] = "string",
	[MGMT_ATTR_CONNECTION_REQUEST_PASSWORD] = "string",
};

static const struct blobmsg_policy server_policy[__MGMT_ATTR_MAX] = {
	[MGMT_ATTR_URL] = { .name = "url", .type = BLOBMSG_TYPE_STRING },
	[MGMT_ATTR_USERNAME] = { .name = "username", .type = BLOBMSG_TYPE_STRING },
	[MGMT_ATTR_PASSWORD] = { .name = "password", .type = BLOBMSG_TYPE_STRING },
	[MGMT_ATTR_PERIODIC_ENABLED] = { .name = "periodic_enabled", .type = BLOBMSG_TYPE_INT8 },
	[MGMT_ATTR_PERIODIC_INTERVAL] = { .name = "periodic_interval", .type = BLOBMSG_TYPE_INT32 },
	[MGMT_ATTR_CONNECTION_REQUEST_USERNAME] = { .name = "local_username", .type = BLOBMSG_TYPE_STRING },
	[MGMT_ATTR_CONNECTION_REQUEST_PASSWORD] = { .name = "local_password", .type = BLOBMSG_TYPE_STRING },
};

static void server_receive_values(struct ubus_request *req, int type, struct blob_attr *msg)
{
	static const struct blobmsg_policy port_policy = {
		.name = "connection_port", .type = BLOBMSG_TYPE_INT32,
	};
	struct blob_attr *tb[__MGMT_ATTR_MAX];
	struct blob_attr *tb_port;
	int i;

	blobmsg_parse(server_policy, ARRAY_SIZE(server_policy), tb, blob_data(msg), blob_len(msg));
	blobmsg_parse(&port_policy, 1, &tb_port, blob_data(msg), blob_len(msg));

	for (i = 0; i < __MGMT_ATTR_MAX; i++) {
		free(server_values[i]);
		server_values[i] = NULL;

		if (!tb[i])
			continue;

		switch (server_policy[i].type) {
		case BLOBMSG_TYPE_STRING:
			server_values[i] = strdup(blobmsg_data(tb[i]));
			break;
		case BLOBMSG_TYPE_INT32:
			asprintf(&server_values[i], "%d", blobmsg_get_u32(tb[i]));
			break;
		case BLOBMSG_TYPE_INT8:
			asprintf(&server_values[i], "%d", blobmsg_get_bool(tb[i]));
			break;
		default:
			break;
		}
	}

	if (tb_port)
		conn_req_port = blobmsg_get_u32(tb_port);

}

static void server_load_values(void)
{
	ubus_invoke(ubus_ctx, cwmp_id, "server_info_get", b.head,
		    server_receive_values, NULL, 0);
}


static int server_commit(struct cwmp_object *obj)
{
	int i;

	blob_buf_init(&b, 0);
	for (i = 0; i < ARRAY_SIZE(server_params); i++) {
		const char *name = server_policy[i].name;
		const char *value = server_values[i];

		if (!value)
			continue;

		switch (server_policy[i].type) {
		case BLOBMSG_TYPE_STRING:
			blobmsg_add_string(&b, name, value);
			break;
		case BLOBMSG_TYPE_INT32:
			blobmsg_add_u32(&b, name, atoi(value));
			break;
		case BLOBMSG_TYPE_INT8:
			blobmsg_add_u8(&b, name, !!atoi(value));
			break;
		default:
			break;
		}
	}

	ubus_invoke(ubus_ctx, cwmp_id, "server_info_set", b.head, NULL, NULL, 0);
	return 0;
}

static unsigned long server_writable =
	((1 << ARRAY_SIZE(server_params)) - 1) &
	~(1 << MGMT_ATTR_CONNECTION_REQUEST_URL);

static unsigned long server_write_only =
	(1 << MGMT_ATTR_PASSWORD) |
	(1 << MGMT_ATTR_CONNECTION_REQUEST_PASSWORD);

static struct cwmp_object server_object = {
	.params = server_params,
	.param_types = server_types,
	.values = server_values,
	.n_params = ARRAY_SIZE(server_params),
	.writable = &server_writable,
	.write_only = &server_write_only,
	.commit = server_commit,
};

#define devinfo_main_fields(t, p) \
	_v(t, p, Manufacturer) \
	_v(t, p, ManufacturerOUI) \
	_v(t, p, ModelName) \
	_v(t, p, Description) \
	_v(t, p, ProductClass) \
	_v(t, p, SerialNumber) \
	_v(t, p, HardwareVersion) \
	_v(t, p, SoftwareVersion) \
	_v(t, p, ModemFirmwareVersion) \
	_v(t, p, AdditionalHardwareVersion) \
	_v(t, p, AdditionalSoftwareVersion) \

#define devinfo_extra_fields(t, p) \
	_v(t, p, SpecVersion)

#define devinfo_fields(t, p) \
	devinfo_main_fields(t, p) \
	devinfo_extra_fields(t, p)

enum devinfo_fields {
	CWMP_ENUM(DEVINFO, devinfo_fields)
	__DEVINFO_MAX
};

static const char *devinfo_param_names[__DEVINFO_MAX] = {
	CWMP_PARAM_NAMES(DEVINFO, devinfo_fields)
};

static char *devinfo_values[__DEVINFO_MAX];

static struct cwmp_object devinfo_object = {
	.params = devinfo_param_names,
	.values = devinfo_values,
	.n_params = __DEVINFO_MAX,
};

void server_update_local_addr(const char *addr)
{
	char **var = &server_values[MGMT_ATTR_CONNECTION_REQUEST_URL];

	free(*var);
	*var = NULL;

	asprintf(var, "http://%s:%d/connreq", addr, conn_req_port);
}

void server_load_info(const char *filename)
{
	static const struct blobmsg_policy devinfo_policy[__DEVINFO_MAX] = {
		CWMP_BLOBMSG_STRING(DEVINFO, devinfo_main_fields)
	};
	struct blob_attr *tb[__DEVINFO_MAX];
	static struct blob_buf b;
	int i;

	memset(devinfo_values, 0, sizeof(devinfo_values));

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
	server_load_values();

	cwmp_object_add(&server_object, "ManagementServer", NULL);
	cwmp_object_add(&devinfo_object, "DeviceInfo", NULL);
}

void cwmp_notify_completed(void)
{
	blob_buf_init(&b, 0);
	ubus_invoke(ubus_ctx, cwmp_id, "session_completed", b.head, NULL, NULL, 0);
}
