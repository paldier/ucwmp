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
#include "backend.h"
#include "scal.h"
#include "object.h"

static struct scal_ctx scal;

void server_update_local_addr(const char *addr, const char *port)
{
	//blobmsg_printf(&vars, "cwmp_local_addr", "%s:%s", addr, port);
	//acs_set_script_data(&api, vars.head);
}

void backend_init(struct ubus_context *ubus_ctx)
{
	scal_init(&scal, ubus_ctx);
	scal_set_module(&scal, "tr-181");
}

void backend_deinit()
{
	scal_deinit(&scal);
}

static void add_parameters(struct cwmp_iterator *it,
				const char *path,
				struct blob_attr *params)
{
	union cwmp_any u = {};
	struct blob_attr *p;
	int rem;
	char buf[CWMP_PATH_LEN];
	char *cur;

	u.param.path = buf;
	cur = buf + sprintf(buf, "%s.", path);

	blobmsg_for_each_attr(p, params, rem) {
		const struct blobmsg_hdr *hdr = blob_data(p);
		const char *name = (char *)hdr->name;
		struct blob_attr *rd_only = get_blob(p, "readonly");;

		strcpy(cur, name);
		u.param.name = name;

		if (rd_only)
			u.param.writeable = !blobmsg_get_u8(rd_only);
		else
			u.param.writeable = false;

		it->cb(it, &u);
		it->cb_call_cnt++;
	}
}

static void add_instances(struct cwmp_iterator *it,
			const char *path,
			struct blob_attr *instances,
			struct blob_attr *params)
{
	char i_path[CWMP_PATH_LEN];
	struct blob_attr *i;
	char *cur = i_path + snprintf(i_path, sizeof(i_path), "%s.", path);
	int rem;

	blobmsg_for_each_attr(i, instances, rem) {
		const struct blobmsg_hdr *hdr = blob_data(i);
		const char *i_name = (char *)hdr->name;

		strcpy(cur, i_name);
		add_parameters(it, i_path, params);
	}
}

static void get_parameter_names_rec(struct cwmp_iterator *it, char *path)
{
	struct blob_attr *objs = NULL;
	struct blob_attr *params = NULL;
	struct blob_attr *obj;
	int rem;

	scal_list(&scal, path, &objs);
	if (objs == NULL)
		return;

	blobmsg_for_each_attr(obj, objs, rem) {
		char sub_path[CWMP_PATH_LEN + 4];
		const struct blobmsg_hdr *hdr = blob_data(obj);
		const char *obj_name = (char *)hdr->name;

		snprintf(sub_path, sizeof(sub_path), "%s.%s", path, obj_name);
		scal_info(&scal, sub_path, &params, NULL);

		if (get_blob(obj, "multi_instance")) {
			struct blob_attr *instances = NULL;

			scal_list(&scal, sub_path, &instances);
			if (instances && params)
				add_instances(it, sub_path, instances, params);
			if (instances) {
				free(instances);
				instances = NULL;
			}
		} else {
			if (params)
				add_parameters(it, sub_path, params);
		}

		if (params) {
			free(params);
			params = NULL;
		}
		get_parameter_names_rec(it, sub_path);
	}
	free(objs);
}

int backend_get_parameter_names(struct cwmp_iterator *it, bool nxt_lvl)
{
	struct blob_attr *params = NULL;
	bool multi_inst_obj = false;

	printf("get param names: %s next level %d\n", it->path, nxt_lvl);

	scal_info(&scal, it->path, &params, &multi_inst_obj);
	if (params) {
		if (multi_inst_obj) {
			struct blob_attr *instances = NULL;

			scal_list(&scal, it->path, &instances);
			if (instances) {
				add_instances(it, it->path, instances, params);
				free(instances);
				instances = NULL;
			}
		} else {
			add_parameters(it, it->path, params);
		}
		free(params);
		params = NULL;
	}

	if (nxt_lvl == true)
		return it->cb_call_cnt;

	get_parameter_names_rec(it, it->path);
	return it->cb_call_cnt;
}

static int _get_parameter_values(struct cwmp_iterator *it,
				struct blob_attr *params)
{
	struct blob_attr *p;
	int rc = 0;
	int len;
	int rem;

	len = strlen(it->path);
	it->path[len++] = '.';

	blobmsg_for_each_attr(p, params, rem) {
		strcpy(&it->path[len], blobmsg_name(p));
		rc += scal_get(&scal, it);
	}
	return rc;
}

static int get_parameter_values(struct cwmp_iterator *it)
{
	struct blob_attr *params = NULL;
	int rc = 0;
	int rem;
	unsigned len;
	bool multi_inst_obj = false;

	scal_info(&scal, it->path, &params, &multi_inst_obj);

	if (multi_inst_obj) {
		struct blob_attr *instances;
		struct blob_attr *i;

		scal_list(&scal, it->path, &instances);
		len = strlen(it->path);
		it->path[len++] = '.';

		blobmsg_for_each_attr(i, instances, rem) {
			strcpy(&it->path[len], blobmsg_name(i));
			rc += _get_parameter_values(it, params);
		}
	} else {
		rc = _get_parameter_values(it, params);
	}
	return rc;
}

int backend_get_parameter_value(struct cwmp_iterator *it, bool nxt_lvl)
{
	int rc;

	if (nxt_lvl)
		rc = get_parameter_values(it);
	else
		rc = scal_get(&scal, it);

	return rc;
}

int backend_set_parameter_value(const char *path, const char *value)
{
	return scal_set(&scal, path, value);
}

int backend_commit()
{
	int rc = scal_validate(&scal);

	if (rc != -1)
		rc = scal_commit(&scal);

	return rc;
}
