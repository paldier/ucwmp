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
#include <libubox/blobmsg.h>
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>

#include "state.h"

static AVL_TREE(objects, avl_strcmp, false, NULL);
static struct blob_buf b;

struct cwmp_object_cache {
	struct avl_node avl;

	int seq;
	struct blob_attr data[];
};

static int
cwmp_object_get_seq(int *seq, const char *name, struct blob_attr *prev)
{
	struct blob_attr *cur;
	int rem;

	if (!prev)
		goto out;

	blobmsg_for_each_attr(cur, prev, rem) {
		char *cur_name;

		if (strcmp(blobmsg_name(cur), name) != 0)
			continue;

		/* clear name here so that we can find deleted objects later */
		cur_name = (char *) blobmsg_name(cur);
		*cur_name = 0;

		return blobmsg_get_u32(cur);
	}

out:
	return ++(*seq);
}

static void
cwmp_object_cache_free(struct cwmp_object_cache *cache)
{
	avl_delete(&objects, &cache->avl);
	free(cache);
}

static void
cwmp_object_delete_old(struct cwmp_object_cache *cache)
{
	struct cwmp_object_cache *cache_cur;
	struct blob_attr *cur;
	const char *base_name;
	int base_len;
	int rem;

	base_name = blobmsg_name(cache->data);
	base_len = strlen(base_name);

	blobmsg_for_each_attr(cur, cache->data, rem) {
		if (!blobmsg_name(cur)[0])
			continue;

		cache_cur = cache;

		while (cache_cur != avl_last_element(&objects, cache, avl)) {
			const char *name;

			cache_cur = avl_next_element(cache_cur, avl);
			name = cache_cur->avl.key;

			if (strncmp(name, base_name, base_len) != 0 ||
				name[base_len] != '.')
				break;

			if (strcmp(&name[base_len + 1], blobmsg_name(cur)) != 0)
				continue;

			cwmp_object_cache_free(cache_cur);
			break;
		}
	}
}

static struct blob_attr *
cwmp_object_cache_add(struct blob_attr *data, int seq)
{
	struct cwmp_object_cache *cache;

	cache = calloc(1, sizeof(*cache) + blob_pad_len(data));
	memcpy(cache->data, data, blob_pad_len(data));
	cache->avl.key = blobmsg_name(cache->data);
	cache->seq = seq;
	avl_insert(&objects, &cache->avl);

	cwmp_save_cache(false);
	return cache->data;
}

struct blob_attr *cwmp_object_cache_get(const char *path, struct blob_attr *list)
{
	struct cwmp_object_cache *cache;
	struct blob_attr *cur, *cache_data = NULL;
	void *c;
	int rem;
	int seq = 0;

	cache = avl_find_element(&objects, path, cache, avl);
	if (cache) {
		seq = cache->seq;
		cache_data = cache->data;
	}

	blob_buf_init(&b, 0);
	c = blobmsg_open_table(&b, path);
	blobmsg_for_each_attr(cur, list, rem) {
		int cur_seq;

		cur_seq = cwmp_object_get_seq(&seq, blobmsg_data(cur), cache_data);
		blobmsg_add_u32(&b, blobmsg_data(cur), cur_seq);
	}
	blobmsg_close_table(&b, c);

	if (cache) {
		cwmp_object_delete_old(cache);
		cwmp_object_cache_free(cache);
	}

	return cwmp_object_cache_add(blob_data(b.head), seq);
}

void cwmp_object_cache_dump(struct blob_buf *buf)
{
	struct cwmp_object_cache *cache;
	void *c;

	avl_for_each_element(&objects, cache, avl) {
		c = blobmsg_open_array(buf, blobmsg_name(cache->data));
		blobmsg_add_u32(buf, NULL, cache->seq);
		blobmsg_add_field(buf, BLOBMSG_TYPE_TABLE, NULL,
				  blobmsg_data(cache->data), blobmsg_data_len(cache->data));
		blobmsg_close_array(buf, c);
	}
}

static void cwmp_object_cache_free_all(void)
{
	struct cwmp_object_cache *cache, *next;

	avl_remove_all_elements(&objects, cache, avl, next)
		free(cache);
}

void cwmp_object_cache_load(struct blob_attr *data)
{
	static const struct blobmsg_policy policy[] = {
		{ NULL, BLOBMSG_TYPE_INT32 },
		{ NULL, BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *tb[2];
	struct blob_attr *cur;
	int rem;

	cwmp_object_cache_free_all();

	blobmsg_for_each_attr(cur, data, rem) {
		blobmsg_parse_array(policy, 2, tb, blobmsg_data(cur), blobmsg_data_len(cur));

		if (!tb[0] || !tb[1])
			continue;

		blob_buf_init(&b, 0);
		blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, blobmsg_name(cur),
				  blobmsg_data(tb[1]), blobmsg_data_len(tb[1]));
		cwmp_object_cache_add(blob_data(b.head), blobmsg_get_u32(tb[0]));
	}
}


