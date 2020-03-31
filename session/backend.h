#ifndef BACKEND_H
#define BACKEND_H

#include "../ucwmp.h"
#include "rpc.h"

#include <roxml.h>
#include <libubus.h>
#include <libubox/blobmsg.h>

struct b_cwmp_object {
	const char *name;
};

struct b_cwmp_param {
	const char *path;
	const char *name;
	const char *value;
	const char *type;
	bool writeable;
};

struct b_cwmp_add_object {
	const char *instance_num;
	int status;
};

struct b_cwmp_del_object {
	int status;
};

union cwmp_any {
	struct b_cwmp_object obj;
	struct b_cwmp_param param;
	struct b_cwmp_add_object add_obj;
	struct b_cwmp_del_object del_obj;
};

struct cwmp_iterator;

typedef void (*cwmp_iterator_cb)(struct cwmp_iterator *it, union cwmp_any *data);

struct cwmp_iterator {
	char path[CWMP_PATH_LEN];
	node_t *node;
	void *priv;
	cwmp_iterator_cb cb;
	unsigned cb_call_cnt;
	int error;
};

static inline void cwmp_iterator_init(struct cwmp_iterator *it)
{
	it->path[0] = 0;
	it->node = NULL;
	it->priv = NULL;
	it->cb = NULL;
	it->cb_call_cnt = 0;
	it->error = 0;
}

struct backend {
	void (*init)(struct ubus_context *ctx);
	void (*deinit)();
	int (*get_parameter_names)(struct cwmp_iterator *it, bool next_level);
	int (*get_parameter_value)(struct cwmp_iterator *it, bool next_level);
	int (*set_parameter_value)(const char *path, const char *value);
	int (*get_parameter_values)(node_t *node, cwmp_iterator_cb cb);
	void (*get_parameter_values_init)();
	int (*add_object)(struct cwmp_iterator *it, const char *key);
	int (*del_object)(const char *path, const char *key);
	int (*commit)();
};

extern const struct backend backend;

#endif
