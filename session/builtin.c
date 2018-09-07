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
#include "backend.h"
#include "object.h"
#include "../util.h"

static struct ubus_context *ubus_ctx;
static uint32_t cwmp_id;
static struct blob_buf b;

void cwmp_clear_pending_events(void)
{
	blob_buf_init(&b, 0);
	ubus_invoke(ubus_ctx, cwmp_id, "event_sent", b.head, NULL, NULL, 0);
}


static void __constructor server_init(void)
{
	ubus_ctx = ubus_connect(NULL);
	ubus_lookup_id(ubus_ctx, "cwmp", &cwmp_id);

	backend_init(ubus_ctx);
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
