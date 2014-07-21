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
#include <libacs/client.h>

#include "soap.h"
#include "object.h"

static struct acs_api api;
static bool need_validate;
static struct blob_buf vars;

struct backend_param {
	struct acs_object_param *mgmt;
};

struct backend_object {
	struct cwmp_object cwmp;
	struct acs_object *mgmt;
	struct backend_param *params;
};

void server_update_local_addr(const char *addr, const char *port)
{
	blobmsg_printf(&vars, "cwmp_local_addr", "%s:%s", addr, port);
	acs_set_script_data(&api, vars.head);
}

void cwmp_backend_init(struct ubus_context *ubus_ctx)
{
	blob_buf_init(&vars, 0);
	acs_api_init(&api);
	acs_set_ubus_context(&api, ubus_ctx);
}

void cwmp_backend_load_data(const char *path)
{
	acs_api_load_module(&api, "tr-098");
}

static int backend_get_param(struct cwmp_object *c_obj, int param, const char **value)
{
	struct backend_object *obj = container_of(c_obj, struct backend_object, cwmp);
	struct blob_attr *attr;

	if (acs_param_get(&api, obj->params[param].mgmt, &attr))
		return CWMP_ERROR_INTERNAL_ERROR;

	if (!attr || blobmsg_type(attr) != BLOBMSG_TYPE_STRING)
		*value = "";
	else
		*value = blobmsg_data(attr);

	return 0;
}

static int backend_set_param(struct cwmp_object *c_obj, int param, const char *value)
{
	struct backend_object *obj = container_of(c_obj, struct backend_object, cwmp);

	if (acs_param_set(&api, obj->params[param].mgmt, value))
		return CWMP_ERROR_INTERNAL_ERROR;

	need_validate = true;
	return 0;
}

static int backend_validate(struct cwmp_object *c_obj)
{
	if (!need_validate)
		return 0;

	need_validate = false;
	return acs_validate(&api);
}

static int backend_commit(struct cwmp_object *c_obj)
{
	return acs_commit(&api);
}

static void backend_object_init(struct backend_object *obj)
{
	obj->cwmp.get_param = backend_get_param;
	obj->cwmp.set_param = backend_set_param;
	obj->cwmp.validate = backend_validate;
	obj->cwmp.commit = backend_commit;
}

static void
backend_add_parameters(struct backend_object *obj, const char **param_names,
		       unsigned long *writable)
{
	struct acs_object_param *par;

	obj->cwmp.params = param_names;
	avl_for_each_element(&obj->mgmt->params, par, avl) {
		int idx = obj->cwmp.n_params++;

		param_names[idx] = acs_object_param_name(par);
		obj->params[idx].mgmt = par;
		if (!par->readonly)
		    bitfield_set(writable, idx);
	}
}

static void backend_create_object(struct acs_object *m_obj)
{
	struct cwmp_object *parent;
	struct backend_object *obj;
	struct backend_param *params;
	const char **param_names;
	const char *name;
	unsigned long *writable;

	parent = cwmp_object_path_create(&root_object, acs_object_name(m_obj), &name);
	if (!parent)
		return;

	if (avl_find(&parent->objects, name))
		return;

	obj = calloc_a(sizeof(*obj),
		&params, m_obj->n_params * sizeof(*params),
		&param_names, m_obj->n_params * sizeof(*param_names),
		&writable, BITFIELD_SIZE(m_obj->n_params));

	obj->mgmt = m_obj;
	obj->params = params;
	obj->cwmp.writable = writable;
	backend_add_parameters(obj, param_names, writable);
	backend_object_init(obj);

	cwmp_object_add(&obj->cwmp, name, parent);
}

void cwmp_backend_add_objects(void)
{
	struct acs_object *obj;

	avl_for_each_element(&api.objects, obj, avl)
		backend_create_object(obj);
}
