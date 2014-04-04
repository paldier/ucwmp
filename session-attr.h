#ifndef __UCWMP_SESSION_H
#define __UCWMP_SESSION_H

#include <stdint.h>
#include <libubox/avl.h>

struct param_attr {
	struct avl_node node;

	bool changed;
	bool acl_subscriber;
	uint8_t notification;

	char value[];
};

extern char *attr_cache_file;

struct param_attr *cwmp_attr_cache_get(const char *name);
bool cwmp_attr_cache_load(void);
void cwmp_attr_cache_save(void);

#endif
