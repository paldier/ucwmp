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
#include <string.h>
#include <stdlib.h>

#include "rpc.h"
#include "object.h"

static int cwmp_dot_len(const char *str)
{
	char *next;

	next = strchr(str, '.');
	if (!next)
		return strlen(str);

	return next - str;
}

static int cwmp_object_cmp(const void *k1, const void *k2, void *ptr)
{
	int len1 = cwmp_dot_len(k1);
	int len2 = cwmp_dot_len(k2);
	int len = len1 < len2 ? len1 : len2;

	return strncmp(k1, k2, len);
}

struct cwmp_object root_object = {
	.node.key = "InternetGatewayDevice",

	.objects = AVL_TREE_INIT(root_object.objects, cwmp_object_cmp, 0, NULL),
};

static struct cwmp_object *
cwmp_object_create_empty(struct cwmp_object *parent, const char *name)
{
	struct cwmp_object *obj;
	const char *sep;
	char *name_buf;
	int name_len;

	sep = strchr(name, '.');
	if (sep)
		name_len = sep - name;
	else
		name_len = strlen(name);

	obj = calloc_a(sizeof(*obj), &name_buf, name_len + 1);
	memcpy(name_buf, name, name_len);

	if (cwmp_object_add(obj, name_buf, parent)) {
		free(obj);
		obj = NULL;
	}

	return obj;
}

static void cwmp_object_reset(struct cwmp_object *obj)
{
	while (obj) {
		obj->cur_instance = -1;
		obj = obj->parent;
	}
}

static struct cwmp_object *
__cwmp_object_get(struct cwmp_object *root, const char *path, const char **param, bool create)
{
	struct cwmp_object *obj = root;
	struct cwmp_object *parent = root;
	struct avl_tree *tree;
	const char *cur = path, *next = path;
	bool instance_set = false;
	int i;

	if (!root) {
		obj = &root_object;

		next = strchr(path, '.');
		if (!next)
			return NULL;

		if (strncmp(path, cwmp_object_name(obj), next - path) != 0)
			return NULL;

		next++;
	}

	while (1) {
		cur = next;
		next = strchr(cur, '.');
		if (!next)
			break;

		next++;
		if (!instance_set && obj->get_instances) {
			char *err;
			int seq;

			seq = strtoul(cur, &err, 10);
			if (err && *err)
				return NULL;

			if (obj->get_instances(obj))
				return NULL;

			if (!obj->instances)
				return NULL;

			for (i = 0; i < obj->n_instances; i++) {
				if (obj->instances[i].seq != seq)
					continue;

				instance_set = true;
				obj->cur_instance = i;
				break;
			}

			if (!instance_set)
				return NULL;

			continue;
		}

		instance_set = false;
		tree = &obj->objects;
		parent = obj;
		obj = avl_find_element(tree, cur, obj, node);
		if (!obj && create)
			obj = cwmp_object_create_empty(parent, cur);

		if (!obj)
			return NULL;
	}

	if (param)
		*param = cur;

	return obj;
}

struct cwmp_object *cwmp_object_path_create(struct cwmp_object *root, const char *path, const char **param)
{
	return __cwmp_object_get(root, path, param, true);
}

struct cwmp_object *cwmp_object_get(struct cwmp_object *root, const char *path, const char **param)
{
	return __cwmp_object_get(root, path, param, false);
}

static void cwmp_commit_obj(struct cwmp_object *obj, bool apply)
{
	int i;

	if (!obj->prev_values)
		return;

	for (i = 0; i < obj->n_params; i++) {
		if (!obj->prev_values[i])
			continue;

		if (!apply)
			obj->set_param(obj, i, obj->prev_values[i]);

		free(obj->prev_values[i]);
	}

	free(obj->prev_values);
	obj->prev_values = NULL;

	if (obj->commit)
		obj->commit(obj);
}

static void __cwmp_commit(struct cwmp_object *obj, bool apply)
{
	struct cwmp_object *cur;

	cwmp_commit_obj(obj, apply);

	avl_for_each_element(&obj->objects, cur, node)
		__cwmp_commit(cur, apply);
}

static int __cwmp_validate(struct cwmp_object *obj)
{
	struct cwmp_object *cur;
	int ret;

	avl_for_each_element(&obj->objects, cur, node) {
		ret = __cwmp_validate(cur);
		if (ret)
			return ret;
	}

	if (!obj->validate)
		return 0;

	return obj->validate(obj);
}

int cwmp_commit(bool apply)
{
	int ret = 0;

	if (apply && __cwmp_validate(&root_object)) {
		apply = false;
		ret = -1;
	}

	__cwmp_commit(&root_object, apply);

	return ret;
}

int cwmp_object_get_param_idx(struct cwmp_object *obj, const char *name)
{
	int i;

	for (i = 0; i < obj->n_params; i++)
		if (!strcmp(obj->params[i], name))
			return i;

	return -1;
}

static int simple_object_get_param(struct cwmp_object *obj, int param, const char **value)
{
	*value = obj->values[param];
	return 0;
}

static int simple_object_set_param(struct cwmp_object *obj, int param, const char *value)
{
	free(obj->values[param]);
	obj->values[param] = value ? strdup(value) : NULL;
	return 0;
}

int cwmp_object_add(struct cwmp_object *obj, const char *name, struct cwmp_object *parent)
{
	obj->cur_instance = -1;

	if (!obj->get_param)
		obj->get_param = simple_object_get_param;

	if (!obj->set_param)
		obj->set_param = simple_object_set_param;

	obj->parent = parent;
	obj->node.key = name;
	if (!parent)
		parent = &root_object;

	avl_init(&obj->objects, cwmp_object_cmp, 0, NULL);
	return avl_insert(&parent->objects, &obj->node);
}

void cwmp_object_delete(struct cwmp_object *obj)
{
	avl_delete(&obj->parent->objects, &obj->node);
	free(obj->prev_values);
	obj->prev_values = NULL;
}

bool cwmp_object_param_writable(struct cwmp_object *obj, int param)
{
	if (!obj->writable)
		return false;

	return bitfield_test(obj->writable, param);
}

static bool cwmp_object_param_write_only(struct cwmp_object *obj, int param)
{
	if (!obj->write_only)
		return false;

	return bitfield_test(obj->write_only, param);
}

static int
__cwmp_param_set(struct cwmp_object *obj, const char *param, const char *value)
{
	int i;

	if (!obj->set_param)
		return CWMP_ERROR_READ_ONLY_PARAM;

	i = cwmp_object_get_param_idx(obj, param);
	if (i < 0)
		return CWMP_ERROR_INVALID_PARAM;

	if (!cwmp_object_param_writable(obj, i))
		return CWMP_ERROR_READ_ONLY_PARAM;

	if (!obj->prev_values)
		obj->prev_values = calloc(obj->n_params, sizeof(*obj->prev_values));

	if (!obj->prev_values[i]) {
		const char *val;

		obj->get_param(obj, i, &val);
		if (val)
			obj->prev_values[i] = strdup(val);
	}

	return obj->set_param(obj, i, value);
}

int cwmp_param_set(const char *name, const char *value)
{
	struct cwmp_object *obj;
	const char *param_str;
	int ret;

	obj = cwmp_object_get(NULL, name, &param_str);
	if (!obj)
		return CWMP_ERROR_INVALID_PARAM;

	ret = __cwmp_param_set(obj, param_str, value);
	cwmp_object_reset(obj);

	return ret;
}

const char *cwmp_object_get_param(struct cwmp_object *obj, int i)
{
	const char *value;

	if (!obj->get_param)
		return NULL;

	if (cwmp_object_param_write_only(obj, i))
		return "";

	if (obj->get_param(obj, i, &value))
		return NULL;

	if (!value)
		value = "";

	return value;
}

const char *cwmp_param_get(const char *name, const char **type)
{
	struct cwmp_object *obj;
	const char *param_str;
	int i;

	obj = cwmp_object_get(NULL, name, &param_str);
	if (!obj)
		return NULL;

	i = cwmp_object_get_param_idx(obj, param_str);
	if (i < 0)
		return NULL;

	if (type)
		*type = obj->param_types ? obj->param_types[i] : NULL;

	return cwmp_object_get_param(obj, i);
}

static int fill_path(struct path_iterate *it, int ofs, const char *name)
{
	int len = strlen(name);

	if (ofs + len + 1 >= sizeof(it->path))
		return -1;

	strcpy(it->path + ofs, name);

	return ofs + len;
}

static int __cwmp_path_iterate(struct path_iterate *it, struct cwmp_object *obj, int ofs, bool next);

static int
__cwmp_path_iterate_obj(struct path_iterate *it, struct cwmp_object *obj,
			int ofs, bool next)
{
	struct cwmp_object *cur;
	int n = 0;

	avl_for_each_element(&obj->objects, cur, node) {
		int ofs_cur = fill_path(it, ofs, cwmp_object_name(cur));

		strcpy(it->path + ofs_cur, ".");
		ofs_cur++;

		n += it->cb(it, cur, -1);
		if (next)
			continue;

		n += __cwmp_path_iterate(it, cur, ofs_cur, false);
	}

	return n;
}

static int __cwmp_path_iterate(struct path_iterate *it, struct cwmp_object *obj, int ofs, bool next)
{
	int n = 0;
	int i;

	for (i = 0; i < obj->n_params; i++) {
		if (fill_path(it, ofs, obj->params[i]) < 0)
			continue;

		n += it->cb(it, obj, i);
	}

	if (!obj->get_instances)
	    return n + __cwmp_path_iterate_obj(it, obj, ofs, next);

	if (obj->get_instances(obj) || !obj->instances)
		return n;


	for (i = 0; i < obj->n_instances; i++) {
		int ofs_cur = ofs;

		ofs_cur += snprintf(it->path + ofs_cur, sizeof(it->path) - ofs_cur,
				    "%d.", obj->instances[i].seq);
		n += it->cb(it, obj, -2);

		if (!next)
			continue;

		n += __cwmp_path_iterate_obj(it, obj, ofs_cur, false);
	}

	return n;
}

int cwmp_path_iterate(struct path_iterate *it, bool next)
{
	struct cwmp_object *obj;
	const char *param;
	bool empty;
	int idx;
	int n;

	empty = !strlen(it->path);
	if (empty)
		snprintf(it->path, sizeof(it->path), "%s.", cwmp_object_name(&root_object));

	obj = cwmp_object_get(NULL, it->path, &param);
	if (!obj) {
		it->error = CWMP_ERROR_INVALID_PARAM;
		return 0;
	}

	if (next && *param) {
		it->error = CWMP_ERROR_INVALID_ARGUMENTS;
		return 0;
	}

	if (!*param) {
		n = it->cb(it, obj, -1);
		if (!empty || !next)
			n += __cwmp_path_iterate(it, obj, param - it->path, next);

		return n;
	}

	idx = cwmp_object_get_param_idx(obj, param);
	if (idx < 0) {
		it->error = -CWMP_ERROR_INVALID_PARAM;
		return 0;
	}

	return it->cb(it, obj, idx);
}
