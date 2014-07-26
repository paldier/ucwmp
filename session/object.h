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
#ifndef __UCWMP_OBJECT_H
#define __UCWMP_OBJECT_H

#include <libubox/avl.h>
#include <libubox/utils.h>

#include "rpc.h"

struct ubus_context;

struct cwmp_object_instance {
	const char *name;
	int seq;

	char **prev_values;
};

struct cwmp_object {
	struct avl_node node;

	struct cwmp_object *parent;
	struct avl_tree objects;

	const char * const *params;
	const char * const *param_types;
	char **values;
	int n_params;

	struct cwmp_object_instance root_instance;
	struct cwmp_object_instance *instances;
	int n_instances;
	int cur_instance;

	unsigned long *writable;
	unsigned long *write_only;

	int (*commit)(struct cwmp_object *obj);
	int (*validate)(struct cwmp_object *obj);

	int (*get_instances)(struct cwmp_object *obj);

	int (*get_param)(struct cwmp_object *obj, int param, const char **value);
	int (*set_param)(struct cwmp_object *obj, int param, const char *value);
};

struct path_iterate {
	char path[CWMP_PATH_LEN];
	node_t *node;
	int error;

	int (*cb)(struct path_iterate *it, struct cwmp_object *obj, int i);
};

extern struct cwmp_object root_object;

int cwmp_path_iterate(struct path_iterate *it, bool next);

int cwmp_param_set(const char *name, const char *value);
const char *cwmp_param_get(const char *name, const char **type);
int cwmp_commit(bool apply);

int cwmp_object_add(struct cwmp_object *obj, const char *name, struct cwmp_object *parent);
void cwmp_object_delete(struct cwmp_object *obj);
struct cwmp_object *cwmp_object_get(struct cwmp_object *root, const char *path, const char **param);
struct cwmp_object *cwmp_object_path_create(struct cwmp_object *root, const char *path, const char **param);
const char *cwmp_object_get_param(struct cwmp_object *obj, int i);
int cwmp_object_get_param_idx(struct cwmp_object *obj, const char *name);
struct blob_attr *
cwmp_get_cache_instances(const char *path, struct blob_attr *data);


static inline const char *cwmp_object_name(struct cwmp_object *obj)
{
	return obj->node.key;
}

bool cwmp_object_param_writable(struct cwmp_object *obj, int param);

void cwmp_backend_init(struct ubus_context *ubus_ctx);
void cwmp_backend_add_objects(void);
void cwmp_backend_load_data(const char *path);

#endif
