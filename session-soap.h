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
#ifndef __UCWMP_SOAP_H
#define __UCWMP_SOAP_H

#include <time.h>
#include <roxml.h>

enum soap_response {
	SOAP_RESPONSE_NONE,
	SOAP_RESPONSE_DATA,
	SOAP_RESPONSE_EMPTY,
};

struct xml_kv {
	const char *name;
	const char *value;
};

void xml_add_multi(node_t *node, int type, int n_kv, const struct xml_kv *kv,
		   node_t **nodes);

node_t *soap_add_time(node_t *node, const char *name, struct tm *val);

char *soap_init_session(void);
char *soap_handle_msg(char *message);
node_t *soap_add_fault(node_t *node, int code);
void soap_add_fault_struct(node_t *node, unsigned int code);

char *__soap_get_field(node_t *node, const char *name, char *buf, int len);
static inline char *soap_get_field(node_t *node, const char *name)
{
	return __soap_get_field(node, name, NULL, 0);
}
int soap_get_boolean_field(node_t *node, const char *name, bool *val);
int soap_get_int_field(node_t *node, const char *name, int *val);

node_t *soap_array_start(node_t *node, const char *name, int *len);
bool soap_array_iterate(node_t **cur, const char *type, node_t **node);
bool soap_array_iterate_contents(node_t **cur, const char *type, char **str);

#endif
