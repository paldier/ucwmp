#include <string.h>
#include <stdlib.h>

#include "cwmp.h"
#include "object.h"

static int cwmp_dot_len(const char *str)
{
	char *next;

	next = strchr(str, '.');
	if (!next)
		return strlen(str);

	return next - str;
}

static int cwmp_object_cmp(const void *k1, const void *k2, void *ptr)
{
	int len1 = cwmp_dot_len(k1);
	int len2 = cwmp_dot_len(k2);
	int len = len1 < len2 ? len1 : len2;

	return strncmp(k1, k2, len);
}

struct cwmp_object root_object = {
	.node.key = "InternetGatewayDevice",

	.objects = AVL_TREE_INIT(root_object.objects, cwmp_object_cmp, 0, NULL),
};

struct cwmp_object *cwmp_object_get(struct cwmp_object *root, const char *path, const char **param)
{
	struct cwmp_object *obj = root;
	struct avl_tree *tree;
	const char *cur = path, *next;

	if (!root) {
		obj = &root_object;

		next = strchr(path, '.');
		if (!next)
			return NULL;

		if (strncmp(path, obj->node.key, next - path) != 0)
			return NULL;

		cur = next + 1;
	}

	while (1) {
		next = strchr(cur, '.');
		if (!next)
			break;

		next++;
		if (obj->fetch_objects && obj->fetch_objects(obj))
			return NULL;

		tree = &obj->objects;
		obj = avl_find_element(tree, cur, obj, node);
		if (!obj)
			return NULL;

		cur = next;
	}

	if (param)
		*param = cur;

	return obj;
}

static void cwmp_commit_obj(struct cwmp_object *obj, bool apply)
{
	int i;

	if (!obj->prev_values)
		return;

	for (i = 0; i < obj->n_params; i++) {
		if (!obj->prev_values[i])
			continue;

		if (!apply)
			obj->set_param(obj, i, obj->prev_values[i]);

		free(obj->prev_values[i]);
	}

	free(obj->prev_values);
	obj->prev_values = NULL;

	if (obj->commit)
		obj->commit(obj);
}

static void __cwmp_commit(struct cwmp_object *obj, bool apply)
{
	struct cwmp_object *cur;

	cwmp_commit_obj(obj, apply);

	avl_for_each_element(&obj->objects, cur, node)
		__cwmp_commit(cur, apply);
}

void cwmp_commit(bool apply)
{
	__cwmp_commit(&root_object, apply);
}

int cwmp_object_get_param_idx(struct cwmp_object *obj, const char *name)
{
	int i;

	for (i = 0; i < obj->n_params; i++)
		if (!strcmp(obj->params[i], name))
			return i;

	return -1;
}

static int simple_object_get_param(struct cwmp_object *obj, int param, const char **value)
{
	*value = obj->values[param];
	return 0;
}

static int simple_object_set_param(struct cwmp_object *obj, int param, const char *value)
{
	free(obj->values[param]);
	obj->values[param] = value ? strdup(value) : NULL;
	return 0;
}

int cwmp_object_add(struct cwmp_object *obj, const char *name, struct cwmp_object *parent)
{
	if (!obj->get_param)
		obj->get_param = simple_object_get_param;

	if (!obj->set_param)
		obj->set_param = simple_object_set_param;

	obj->parent = parent;
	obj->node.key = name;
	if (!parent)
		parent = &root_object;

	avl_init(&obj->objects, cwmp_object_cmp, 0, NULL);
	return avl_insert(&parent->objects, &obj->node);
}

void cwmp_object_delete(struct cwmp_object *obj)
{
	avl_delete(&obj->parent->objects, &obj->node);
	free(obj->prev_values);
	obj->prev_values = NULL;
}

bool cwmp_object_param_writable(struct cwmp_object *obj, int param)
{
	if (!obj->writable)
		return false;

	return bitfield_test(obj->writable, param);
}

int cwmp_param_set(const char *name, const char *value)
{
	struct cwmp_object *obj;
	const char *param_str;
	int i;

	obj = cwmp_object_get(NULL, name, &param_str);
	if (!obj)
		return CWMP_ERROR_INVALID_PARAM;

	if (!obj->set_param)
		return CWMP_ERROR_READ_ONLY_PARAM;

	i = cwmp_object_get_param_idx(obj, param_str);
	if (i < 0)
		return CWMP_ERROR_INVALID_PARAM;

	if (!cwmp_object_param_writable(obj, i))
		return CWMP_ERROR_READ_ONLY_PARAM;

	if (!obj->prev_values)
		obj->prev_values = calloc(obj->n_params, sizeof(*obj->prev_values));

	if (!obj->prev_values[i]) {
		const char *val;

		obj->get_param(obj, i, &val);
		if (val)
			obj->prev_values[i] = strdup(val);
	}

	return obj->set_param(obj, i, value);
}

static int fill_path(struct path_iterate *it, int ofs, const char *name)
{
	int len = strlen(name);

	if (ofs + len + 1 >= sizeof(it->path))
		return -1;

	strcpy(it->path + ofs, name);

	return ofs + len;
}

static int __cwmp_path_iterate(struct path_iterate *it, struct cwmp_object *obj, int ofs, bool next)
{
	struct cwmp_object *cur;
	int n = 0;
	int i;

	for (i = 0; i < obj->n_params; i++) {
		if (fill_path(it, ofs, obj->params[i]) < 0)
			continue;

		n += it->cb(it, obj, i);
	}

	obj->fetch_objects(obj);
	avl_for_each_element(&obj->objects, cur, node) {
		int ofs_cur = fill_path(it, ofs, obj->node.key);

		strcpy(it->path + ofs_cur, ".");
		ofs_cur++;

		n += it->cb(it, cur, -1);
		if (!next)
			n += __cwmp_path_iterate(it, cur, ofs_cur, next);
	}

	return n;
}

int cwmp_path_iterate(struct path_iterate *it, bool next)
{
	struct cwmp_object *obj;
	const char *param;
	int idx;

	obj = cwmp_object_get(NULL, it->path, &param);
	if (!obj) {
		it->error = CWMP_ERROR_INVALID_PARAM;
		return 0;
	}

	if (next && *param) {
		it->error = CWMP_ERROR_INVALID_ARGUMENTS;
		return 0;
	}

	if (!*param)
		return __cwmp_path_iterate(it, obj, param - it->path, next);

	idx = cwmp_object_get_param_idx(obj, param);
	if (idx < 0) {
		it->error = -CWMP_ERROR_INVALID_PARAM;
		return 0;
	}

	return it->cb(it, obj, idx);
}
