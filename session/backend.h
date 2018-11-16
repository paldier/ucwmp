#ifndef BACKEND_H
#define BACKEND_H

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
	it->node = 0;
	it->priv = NULL;
	it->cb = NULL;
	it->cb_call_cnt = 0;
	it->error = 0;
}

void backend_init(struct ubus_context *ubus_ctx);
void backend_deinit();
int backend_get_parameter_names(struct cwmp_iterator *it, bool nxt_lvl);
int backend_get_parameter_value(struct cwmp_iterator *it, bool nxt_lvl);
int backend_set_parameter_value(const char *path, const char *value);
int backend_commit();

static inline struct blob_attr *
get_blob(struct blob_attr *data, const char *name)
{
	const struct blobmsg_policy policy = { name, BLOBMSG_TYPE_UNSPEC };
	struct blob_attr *attr;

	blobmsg_parse(&policy, 1, &attr,
			blobmsg_data(data),
			blobmsg_data_len(data));
	return attr;
}

#endif
