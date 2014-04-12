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

#include <libubox/blobmsg_json.h>

#include "mgmt_backend.h"

static void dump_params(struct mgmt_object *obj)
{
	struct mgmt_object_param *par;

	avl_for_each_element(&obj->params, par, avl) {
		char *str;

		str = blobmsg_format_json(par->backend_data, true);
		fprintf(stderr, "\t%s(%s) => %s:%s\n",
			mgmt_object_param_name(par), par->type,
			mgmt_backend_name(par->backend), str);
		free(str);
	}
}

static void dump_objects(struct mgmt_backend_api *ctx)
{
	struct mgmt_object *obj;

	avl_for_each_element(&ctx->objects, obj, avl) {
		fprintf(stderr, "%s:\n", mgmt_object_name(obj));
		dump_params(obj);
	}
}

int main(int argc, char **argv)
{
	static struct mgmt_backend_api api;
	int i;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <files>\n", argv[0]);
		return 1;
	}

	mgmt_backend_api_init(&api);
	for (i = 1; i < argc; i++)
		mgmt_backend_api_load_all(&api, argv[i]);

	dump_objects(&api);
	mgmt_backend_api_free(&api);

	return 0;
}
