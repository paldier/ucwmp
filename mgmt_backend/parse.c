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
#include <stdio.h>
#include <glob.h>

#include <libubox/blobmsg_json.h>
#include <libubox/kvlist.h>
#include <libubox/utils.h>
#include <libubox/avl-cmp.h>

#include "client.h"

static struct blob_buf obj_buf, b;

static struct mgmt_object *mgmt_object_get(struct mgmt_backend_api *ctx, const char *name)
{
	struct mgmt_object *obj;
	char *name_buf;

	obj = avl_find_element(&ctx->objects, name, obj, avl);
	if (obj)
		return obj;

	obj = calloc_a(sizeof(*obj), &name_buf, strlen(name) + 1);
	obj->avl.key = strcpy(name_buf, name);
	avl_init(&obj->params, avl_strcmp, false, NULL);
	avl_insert(&ctx->objects, &obj->avl);

	return obj;
}

static struct mgmt_backend *mgmt_backend_get(struct mgmt_backend_api *ctx, const char *name)
{
	struct mgmt_backend *obj;
	char *name_buf;

	obj = avl_find_element(&ctx->backends, name, obj, avl);
	if (obj)
		return obj;

	obj = calloc_a(sizeof(*obj), &name_buf, strlen(name) + 1);
	obj->avl.key = strcpy(name_buf, name);
	avl_insert(&ctx->backends, &obj->avl);

	return obj;
}

static void
merge_backend_data(struct blob_buf *buf, struct blob_attr *base, struct blob_attr *param)
{
	static struct kvlist kv;
	struct blob_attr *cur;
	const char *name;
	int rem;

	kvlist_init(&kv, kvlist_blob_len);

	blobmsg_for_each_attr(cur, base, rem)
		kvlist_set(&kv, blobmsg_name(cur), cur);
	blobmsg_for_each_attr(cur, param, rem)
		kvlist_set(&kv, blobmsg_name(cur), cur);

	kvlist_for_each(&kv, name, cur)
		blobmsg_add_blob(buf, cur);

	kvlist_free(&kv);
}

static void
mgmt_object_param_add(struct mgmt_backend_api *ctx, struct mgmt_object *obj, struct blob_attr *data,
		      const char *backend_name, struct blob_attr *backend_data)
{
	enum {
		PARAM_TYPE,
		PARAM_BACKEND,
		PARAM_BACKEND_DATA,
		__PARAM_MAX
	};
	static const struct blobmsg_policy policy[__PARAM_MAX] = {
		[PARAM_TYPE] = { "type", BLOBMSG_TYPE_STRING },
		[PARAM_BACKEND] = { "backend", BLOBMSG_TYPE_STRING },
		[PARAM_BACKEND_DATA] = { "backend_data", BLOBMSG_TYPE_TABLE },
	};
	struct mgmt_object_param *par;
	struct blob_attr *tb[__PARAM_MAX];
	const char *name = blobmsg_name(data);
	const char *type;
	struct blob_attr *bdata;
	char *type_buf, *name_buf;

	if (!name[0])
		return;

	if (avl_find(&obj->params, name))
		return;

	blobmsg_parse(policy, ARRAY_SIZE(policy), tb, blobmsg_data(data), blobmsg_data_len(data));

	blob_buf_init(&b, 0);

	if (tb[PARAM_TYPE])
		type = blobmsg_data(tb[PARAM_TYPE]);
	else
		type = "";

	if (tb[PARAM_BACKEND]) {
		backend_data = tb[PARAM_BACKEND_DATA];
		backend_name = blobmsg_data(tb[PARAM_BACKEND]);
	} else if (backend_data && tb[PARAM_BACKEND_DATA]) {
		merge_backend_data(&b, backend_data, tb[PARAM_BACKEND_DATA]);
		backend_data = b.head;
	} else {
		backend_data = tb[PARAM_BACKEND_DATA];
	}

	if (!backend_name)
		return;

	if (!backend_data)
		backend_data = b.head;

	par = calloc_a(sizeof(*par),
		&type_buf, strlen(type) + 1,
		&name_buf, strlen(name) + 1,
		&bdata, blob_pad_len(backend_data));

	par->avl.key = strcpy(name_buf, name);
	par->backend = mgmt_backend_get(ctx, backend_name);
	par->type = strcpy(type_buf, type);
	par->backend_data = memcpy(bdata, backend_data, blob_pad_len(backend_data));

	if (avl_insert(&obj->params, &par->avl)) {
		free(par);
		return;
	}

	obj->n_params++;
}

static void
mgmt_object_add(struct mgmt_backend_api *ctx, const char *name, struct blob_attr *attr)
{
	enum {
		OBJ_BACKEND,
		OBJ_BACKEND_DATA,
		OBJ_PARAM,
		__OBJ_MAX
	};
	static const struct blobmsg_policy policy[__OBJ_MAX] = {
		[OBJ_BACKEND] = { "backend", BLOBMSG_TYPE_STRING },
		[OBJ_BACKEND_DATA] = { "backend_data", BLOBMSG_TYPE_TABLE },
		[OBJ_PARAM] = { "parameters", BLOBMSG_TYPE_TABLE },
	};
	struct mgmt_object *obj;
	struct blob_attr *tb[__OBJ_MAX], *cur;
	struct blob_attr *backend_data = NULL;
	const char *backend = NULL;
	int rem;

	blobmsg_parse(policy, ARRAY_SIZE(policy), tb, blobmsg_data(attr), blobmsg_data_len(attr));
	obj = mgmt_object_get(ctx, name);

	if (!tb[OBJ_PARAM])
		return;

	if (tb[OBJ_BACKEND]) {
		backend = blobmsg_data(tb[OBJ_BACKEND]);
		backend_data = tb[OBJ_BACKEND_DATA];
	}

	blobmsg_for_each_attr(cur, tb[OBJ_PARAM], rem)
		mgmt_object_param_add(ctx, obj, cur, backend, backend_data);
}

static void
mgmt_object_attr_add(struct mgmt_backend_api *ctx, struct blob_attr *attr)
{
	struct blobmsg_policy pol[2] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *tb[2];

	BUILD_BUG_ON(ARRAY_SIZE(pol) != ARRAY_SIZE(tb));

	blobmsg_parse_array(pol, ARRAY_SIZE(pol), tb, blobmsg_data(attr), blobmsg_data_len(attr));
	if (!tb[0] || !tb[1])
		return;

	mgmt_object_add(ctx, blobmsg_data(tb[0]), tb[1]);
}

int mgmt_backend_api_load(struct mgmt_backend_api *ctx, const char *path)
{
	static const struct blobmsg_policy obj_p = {
		"objects", BLOBMSG_TYPE_ARRAY
	};
	struct blob_attr *obj_list, *cur;
	int rem;

	blob_buf_init(&obj_buf, 0);
	blobmsg_add_json_from_file(&obj_buf, path);

	blobmsg_parse(&obj_p, 1, &obj_list, blob_data(obj_buf.head), blob_len(obj_buf.head));
	if (!obj_list)
		return -1;

	blobmsg_for_each_attr(cur, obj_list, rem)
		mgmt_object_attr_add(ctx, cur);

	return 0;
}

static void mgmt_backend_free_data(void)
{
	blob_buf_free(&b);
	blob_buf_free(&obj_buf);
}

int mgmt_backend_api_load_all(struct mgmt_backend_api *ctx, const char *path)
{
	glob_t gl;
	int ret;
	int i;

	ret = glob(path, 0, NULL, &gl);
	if (ret)
		return -1;

	for (i = 0; i < gl.gl_pathc; i++)
		mgmt_backend_api_load(ctx, gl.gl_pathv[i]);

	globfree(&gl);
	mgmt_backend_free_data();

	return 0;
}

void mgmt_backend_api_init(struct mgmt_backend_api *ctx)
{
	avl_init(&ctx->objects, avl_strcmp, false, NULL);
	avl_init(&ctx->backends, avl_strcmp, false, NULL);
}

static void mgmt_object_free(struct mgmt_object *obj)
{
	struct mgmt_object_param *p, *tmp;

	avl_remove_all_elements(&obj->params, p, avl, tmp)
		free(p);

	free(obj);
}

static void mgmt_backend_free(struct mgmt_object *b)
{
	free(b);
}

void mgmt_backend_api_free(struct mgmt_backend_api *ctx)
{
	struct mgmt_object *obj, *tmp;

	mgmt_backend_free_data();

	avl_remove_all_elements(&ctx->objects, obj, avl, tmp)
		mgmt_object_free(obj);

	avl_remove_all_elements(&ctx->backends, obj, avl, tmp)
		mgmt_backend_free(obj);
}
