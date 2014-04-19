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
#ifndef __MGMT_BACKEND_H
#define __MGMT_BACKEND_H

#include <libubox/avl.h>

struct mgmt_backend {
	struct avl_node avl;
};

struct mgmt_object_param {
	struct avl_node avl;

	const char *type;
	struct mgmt_backend *backend;
	struct blob_attr *backend_data;
};

struct mgmt_object {
	struct avl_node avl;

	struct avl_tree params;
	int n_params;
};

struct mgmt_backend_api {
	struct avl_tree backends;
	struct avl_tree objects;
};

static inline const char *mgmt_object_name(struct mgmt_object *obj)
{
	return obj->avl.key;
}

static inline const char *mgmt_object_param_name(struct mgmt_object_param *par)
{
	return par->avl.key;
}

static inline const char *mgmt_backend_name(struct mgmt_backend *b)
{
	return b->avl.key;
}

int mgmt_backend_api_load(struct mgmt_backend_api *ctx, const char *path);
int mgmt_backend_api_load_all(struct mgmt_backend_api *ctx, const char *path);

void mgmt_backend_api_init(struct mgmt_backend_api *ctx);
void mgmt_backend_api_free(struct mgmt_backend_api *ctx);

#endif
