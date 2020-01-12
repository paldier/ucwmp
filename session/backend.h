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

union cwmp_any {
	struct b_cwmp_object obj;
	struct b_cwmp_param param;
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
	// del
	// add
	int (*commit)();
};

extern const struct backend backend;

#endif
