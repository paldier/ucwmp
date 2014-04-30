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

struct backend_param {
	struct acs_object_param *mgmt;
};

struct backend_object {
	struct cwmp_object cwmp;
	struct acs_object *mgmt;
	struct backend_param *params;
};

static void __constructor backend_init(void)
{
	acs_api_init(&api);
}

void cwmp_backend_load_data(const char *path)
{
	acs_api_load_module(&api, "tr-098");
}

static int backend_get_param(struct cwmp_object *obj, int param, const char **value)
{
	*value = "N/A";
	return 0;
}

static void backend_object_init(struct backend_object *obj)
{
	obj->cwmp.get_param = backend_get_param;
}

static void backend_add_parameters(struct backend_object *obj, const char **param_names)
{
	struct acs_object_param *par;

	obj->cwmp.params = param_names;
	avl_for_each_element(&obj->mgmt->params, par, avl) {
		int idx = obj->cwmp.n_params++;

		param_names[idx] = acs_object_param_name(par);
		obj->params[idx].mgmt = par;
	}
}

static void backend_create_object(struct acs_object *m_obj)
{
	struct cwmp_object *parent;
	struct backend_object *obj;
	struct backend_param *params;
	const char **param_names;
	const char *name;

	parent = cwmp_object_path_create(&root_object, acs_object_name(m_obj), &name);
	if (!parent)
		return;

	if (avl_find(&parent->objects, name))
		return;

	obj = calloc_a(sizeof(*obj),
		&params, m_obj->n_params * sizeof(*params),
		&param_names, m_obj->n_params * sizeof(*param_names));

	obj->mgmt = m_obj;
	obj->params = params;
	backend_add_parameters(obj, param_names);
	backend_object_init(obj);

	cwmp_object_add(&obj->cwmp, name, parent);
}

void cwmp_backend_add_objects(void)
{
	struct acs_object *obj;

	avl_for_each_element(&api.objects, obj, avl)
		backend_create_object(obj);
}
