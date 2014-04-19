#include <mgmt_backend/client.h>

#include "soap.h"
#include "object.h"

static struct mgmt_backend_api api;

struct backend_param {
	struct mgmt_object_param *mgmt;
};

struct backend_object {
	struct cwmp_object cwmp;
	struct mgmt_object *mgmt;
	struct backend_param *params;
};

static void __constructor backend_init(void)
{
	mgmt_backend_api_init(&api);
}

void cwmp_backend_load_data(const char *path)
{
	mgmt_backend_api_load_all(&api, path);
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
	struct mgmt_object_param *par;

	obj->cwmp.params = param_names;
	avl_for_each_element(&obj->mgmt->params, par, avl) {
		int idx = obj->cwmp.n_params++;

		param_names[idx] = mgmt_object_param_name(par);
		obj->params[idx].mgmt = par;
	}
}

static void backend_create_object(struct mgmt_object *m_obj)
{
	struct cwmp_object *parent;
	struct backend_object *obj;
	struct backend_param *params;
	const char **param_names;
	const char *name;

	parent = cwmp_object_path_create(&root_object, mgmt_object_name(m_obj), &name);
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
	struct mgmt_object *obj;

	avl_for_each_element(&api.objects, obj, avl)
		backend_create_object(obj);
}
