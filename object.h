#ifndef __UCWMP_OBJECT_H
#define __UCWMP_OBJECT_H

#include <libubox/avl.h>
#include <libubox/utils.h>

struct cwmp_object {
	struct avl_node node;

	struct cwmp_object *parent;
	struct avl_tree objects;

	const char **params;
	const char **param_types;
	char **prev_values;
	char **values;
	int n_params;

	unsigned long *writable;

	int (*commit)(struct cwmp_object *obj);
	int (*fetch_objects)(struct cwmp_object *obj);

	int (*get_param)(struct cwmp_object *obj, int param, const char **value);
	int (*set_param)(struct cwmp_object *obj, int param, const char *value);
};

extern struct cwmp_object root_object;

int cwmp_param_set(const char *name, const char *value);
void cwmp_commit(bool apply);

int cwmp_object_add(struct cwmp_object *obj, const char *name, struct cwmp_object *parent);
void cwmp_object_delete(struct cwmp_object *obj);
struct cwmp_object *cwmp_object_get(struct cwmp_object *root, const char *path, const char **param);
int cwmp_object_get_param_idx(struct cwmp_object *obj, const char *name);

bool cwmp_object_param_writable(struct cwmp_object *obj, int param);

#endif
