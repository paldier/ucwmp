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
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "rpc.h"
#include "attr.h"
#include "object.h"

char *attr_cache_file = NULL;

static AVL_TREE(attr_cache, avl_strcmp, false, NULL);
static struct blob_buf b;

static bool cwmp_attr_is_default(struct param_attr *attr)
{
	if (!attr->acl_subscriber)
		return false;

	if (attr->notification)
		return false;

	return true;
}

struct param_attr *cwmp_attr_cache_get(const char *name, bool temp)
{
	static struct param_attr temp_attr;
	struct param_attr *attr;
	const char *value, *type;

	attr = avl_find_element(&attr_cache, name, attr, node);
	if (attr)
		return attr;

	value = cwmp_param_get(name, &type);
	if (!value)
		return NULL;

	if (temp) {
		memset(&temp_attr, 0, sizeof(temp_attr));
		attr = &temp_attr;
	} else {
		char *name_buf, *value_buf;

		attr = calloc_a(sizeof(*attr) + strlen(value) + 1,
				&name_buf, strlen(name) + 1,
				&value_buf, strlen(value) + 1);
		name = strcpy(name_buf, name);
		value = strcpy(value_buf, value);
	}

	attr->node.key = name;
	attr->value = value;
	attr->type = type;
	attr->acl_subscriber = true;

	if (!temp)
		avl_insert(&attr_cache, &attr->node);

	return attr;
}

static bool cwmp_attr_cache_parse(struct blob_attr *data)
{
	enum {
		ATTR_CACHE_NAME,
		ATTR_CACHE_VALUE,
		ATTR_CACHE_NOTIFICATION,
		ATTR_CACHE_ACL_SUBSCRIBER,
		__ATTR_CACHE_MAX,
	};
	static const struct blobmsg_policy policy[__ATTR_CACHE_MAX] = {
		[ATTR_CACHE_NAME] = { .type = BLOBMSG_TYPE_STRING },
		[ATTR_CACHE_VALUE] = { .type = BLOBMSG_TYPE_STRING },
		[ATTR_CACHE_NOTIFICATION] = { .type = BLOBMSG_TYPE_INT32 },
		[ATTR_CACHE_ACL_SUBSCRIBER] = { .type = BLOBMSG_TYPE_INT8 },
	};
	struct blob_attr *tb[__ATTR_CACHE_MAX], *cur;
	struct param_attr *attr;

	blobmsg_parse_array(policy, ARRAY_SIZE(policy), tb, blobmsg_data(data), blobmsg_data_len(data));

	if (!tb[ATTR_CACHE_NAME] || !tb[ATTR_CACHE_VALUE])
		return false;

	attr = cwmp_attr_cache_get(blobmsg_data(tb[ATTR_CACHE_NAME]), false);
	if (!attr)
		return false;

	if ((cur = tb[ATTR_CACHE_NOTIFICATION]))
		attr->notification = blobmsg_get_u32(cur);

	if ((cur = tb[ATTR_CACHE_ACL_SUBSCRIBER]))
		attr->acl_subscriber = blobmsg_get_bool(cur);

	if (!attr->notification)
		return false;

	attr->changed = strcmp(attr->value, blobmsg_data(tb[ATTR_CACHE_VALUE])) != 0;
	return attr->changed;
}

bool cwmp_attr_cache_load(void)
{
	struct param_attr *attr, *next;
	struct blob_attr *cur, *list;
	json_object *obj;
	bool changed = false;
	int rem;

	if (!attr_cache_file)
		return false;

	obj = json_object_from_file(attr_cache_file);
	if (is_error(obj))
		return false;

	blob_buf_init(&b, 0);

	if (json_object_get_type(obj) == json_type_array)
		blobmsg_add_json_element(&b, NULL, obj);

	json_object_put(obj);

	if (!blob_len(b.head))
		return false;

	avl_remove_all_elements(&attr_cache, attr, node, next)
		free(attr);

	list = blob_data(b.head);
	blobmsg_for_each_attr(cur, list, rem)
		changed |= cwmp_attr_cache_parse(cur);

	return changed;
}

static void add_attr(struct param_attr *attr)
{
	void *c;

	if (cwmp_attr_is_default(attr))
		return;

	c = blobmsg_open_array(&b, NULL);
	blobmsg_add_string(&b, NULL, attr->node.key);
	blobmsg_add_string(&b, NULL, attr->value);
	blobmsg_add_u32(&b, NULL, attr->notification);
	blobmsg_add_u8(&b, NULL, attr->acl_subscriber);
	blobmsg_close_array(&b, c);
}

void cwmp_attr_cache_save(void)
{
	struct param_attr *attr;
	char *str;
	void *c;
	FILE *f;

	if (!attr_cache_file)
		return;

	blob_buf_init(&b, 0);

	c = blobmsg_open_array(&b, NULL);

	avl_for_each_element(&attr_cache, attr, node)
		add_attr(attr);

	blobmsg_close_array(&b, c);

	str = blobmsg_format_json(blob_data(b.head), false);
	f = fopen(attr_cache_file, "w");
	if (f) {
		fprintf(f, "%s", str);
		fclose(f);
	}
	free(str);
}

int cwmp_attr_cache_add_changed(node_t *node)
{
	struct param_attr *attr;
	int n = 0;

	avl_for_each_element(&attr_cache, attr, node) {
		if (!attr->changed)
			continue;

		n++;
		cwmp_add_parameter_value_struct(node, attr->node.key, attr->value, attr->type);
	}

	return n;
}
