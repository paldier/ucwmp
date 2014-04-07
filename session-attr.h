#ifndef __UCWMP_SESSION_H
#define __UCWMP_SESSION_H

#include <stdint.h>
#include <libubox/avl.h>

struct param_attr {
	struct avl_node node;

	const char *type;
	const char *value;

	bool changed;
	bool acl_subscriber;
	uint8_t notification;
};

extern char *attr_cache_file;

struct param_attr *cwmp_attr_cache_get(const char *name, bool temp);
bool cwmp_attr_cache_load(void);
void cwmp_attr_cache_save(void);
int cwmp_attr_cache_add_changed(node_t *node);

#endif
