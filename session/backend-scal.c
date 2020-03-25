#include "backend.h"
#include "ubus.h"
#include "blob_helpers.h"

#include <string.h>
#include <inttypes.h>

static struct scal_ctx {
	char ubus_path[32];
	struct ubus_context *ubus_ctx;
	unsigned scald_id;
	int prepared;
	struct blob_buf buf;
} scal;

struct scal_get_req {
	struct cwmp_iterator *it;
	char path[CWMP_PATH_LEN];
	char name[CWMP_PATH_LEN];
	unsigned success;
};

struct copy_cb_args {
	const char *name;
	struct blob_attr **dst;
	bool *multi_inst;
};


static struct blob_attr * get_blob(struct blob_attr *data, const char *name)
{
	const struct blobmsg_policy policy = { name, BLOBMSG_TYPE_UNSPEC };
	struct blob_attr *attr;

	blobmsg_parse(&policy, 1, &attr,
			blobmsg_data(data),
			blobmsg_data_len(data));
	return attr;
}

static void scal_set_module(struct scal_ctx *ctx, const char *mod)
{
	sprintf(ctx->ubus_path, "scald.%s", mod);
	ctx->prepared = 0;
}

static void scal_init(struct ubus_context *ubus)
{
	memset(&scal, 0, sizeof(scal));
	scal.ubus_ctx = ubus;
	scal_set_module(&scal, "tr-181");
}

static void scal_deinit()
{
	blob_buf_free(&scal.buf);
}

static int scald_lookup(struct scal_ctx *ctx)
{
	int err;

	err = ubus_lookup_id(ctx->ubus_ctx, ctx->ubus_path, &ctx->scald_id);
	if (err)
		err_ubus(err, "ubus_lookup %s failed", ctx->ubus_path);

	return !err;
}

static int scal_ctx_prepare(struct scal_ctx *ctx)
{
	if (!ctx->prepared)
		ctx->prepared = scald_lookup(ctx);
	return ctx->prepared;
}

static void scal_set_cb(struct ubus_request *req,
			int type, struct blob_attr *msg)
{
	int *ret = req->priv;

	/* scald only responds to 'set' calls on error */
	*ret = -1;
}

static void cwmp_path_to_array(struct blob_buf *b, const char *path)
{
	char path_buf[CWMP_PATH_LEN];
	char *tok;
	void *a;

	strcpy(path_buf, path);
	blob_buf_init(b, 0);
	a = blobmsg_open_array(b, "path");
	tok = strtok(path_buf, ".");

	if (tok == NULL) {
		blobmsg_add_string(b, NULL, path);
		goto out;
	}
	while (tok) {
		blobmsg_add_string(b, NULL, tok);
		tok = strtok(NULL, ".");
	}
out:
	blobmsg_close_array(b, a);
}

static void copy_cb(struct ubus_request *req,
			int type, struct blob_attr *msg)
{
	struct copy_cb_args *args = req->priv;
	struct blob_attr *attr = get_blob(msg, args->name);

	if (attr)
		*args->dst = blob_memdup(attr);
	else
		*args->dst = NULL;

	if (args->multi_inst)
		*args->multi_inst = !!get_blob(msg, "multi_instance");
}

static int scal_info(struct scal_ctx *ctx, const char *path,
		struct blob_attr **params, bool *multi_inst)
{
	struct copy_cb_args args = {
		.name = "parameters",
		.dst = params,
		.multi_inst = multi_inst
	};
	int err;

	if (!scal_ctx_prepare(ctx))
		return 0;

	cwmp_path_to_array(&ctx->buf, path);

	err = ubus_invoke(ctx->ubus_ctx, ctx->scald_id, "info",
			ctx->buf.head, copy_cb, &args, 1000);
	if (err) {
		err_ubus(err, "ubus_invoke %s->%s %s",
			ctx->ubus_path, "info", path);
		ctx->prepared = 0;
	}
	return !err;
}

static int scal_list(struct scal_ctx *ctx, const char *path, struct blob_attr **objs)
{
	struct copy_cb_args args = {
		.name = "objects",
		.dst = objs
	};
	int err;

	if (!scal_ctx_prepare(ctx))
		return 0;

	cwmp_path_to_array(&ctx->buf, path);

	err = ubus_invoke(ctx->ubus_ctx, ctx->scald_id, "list",
			ctx->buf.head, copy_cb, &args, 1000);
	if (err) {
		err_ubus(err, "ubus_invoke %s->%s %s",
			ctx->ubus_path, "list", path);
		ctx->prepared = 0;
	}
	return !err;
}


static void scal_get_cb(struct ubus_request *req,
			int type, struct blob_attr *msg)
{
	enum {
		P_VAL,
		P_TYPE,
		__P_MAX
	};
	static const struct blobmsg_policy p[] = {
		{ "value", BLOBMSG_TYPE_UNSPEC },
		{ "type", BLOBMSG_TYPE_STRING }
	};
	char buf[32];
	struct scal_get_req *r = req->priv;
	struct blob_attr *tb[__P_MAX];
	union cwmp_any u = {};

	blobmsg_parse(p, __P_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));
	if (tb[P_VAL]) {
		u.param.name = r->name;

		if (tb[P_TYPE])
			u.param.type = blobmsg_get_string(tb[P_TYPE]);
		if (u.param.type == NULL)
			u.param.type = "string";

		u.param.value = blob_any_to_string(tb[P_VAL], buf, sizeof(buf));
		if (u.param.value) {
			r->it->cb(r->it, &u);
			r->success = 1;
		}
	} else {
		err("missing 'value' field in response for '%s.%s'\n",
			r->path, r->name);
		r->it->error = CWMP_ERROR_INTERNAL_ERROR;
	}

	cwmp_debug(1, "scal", "Object '%s' parameter '%s' get value '%s'\n",
		   r->path, r->name, u.param.value);
}

static int split_path_parameter(const char *full_path, char *path, char *param)
{
	const unsigned len_full = strlen(full_path);
	unsigned len = len_full;

	if (len == 0)
		return -1;

	for (len -= 1; len && full_path[len] != '.'; len--)
		;

	if (len >= len_full)
		return -1;

	memcpy(path, full_path, len);
	path[len] = 0;
	strcpy(param, &full_path[len + 1]);
	return 0;
}

static int scal_get_req_init(struct scal_get_req *r, struct cwmp_iterator *it)
{
	if (split_path_parameter(it->path, r->path, r->name) == -1)
		return -1;

	r->it = it;
	r->success = 0;
	return 0;
}

static int scal_get(struct scal_ctx *ctx, struct cwmp_iterator *it)
{
	struct scal_get_req req;
	int err;

	if (!scal_ctx_prepare(ctx))
		return 0;

	if (scal_get_req_init(&req, it) == -1)
		return 0;

	cwmp_path_to_array(&ctx->buf, req.path);
	blobmsg_add_string(&ctx->buf, "name", req.name);
	err = ubus_invoke(ctx->ubus_ctx, ctx->scald_id, "get",
			ctx->buf.head, scal_get_cb, &req, 1000);
	if (err) {
		err_ubus(err, "ubus_invoke %s->%s %s.%s",
			ctx->ubus_path, "get", req.path, req.name);
		ctx->prepared = 0;
	}
	return req.success;
}

static int scal_set(struct scal_ctx *ctx, const char *full_path, const char *value)
{
	char path[CWMP_PATH_LEN];
	char name[CWMP_PATH_LEN];
	int err;
	int ret = 0;

	if (!scal_ctx_prepare(ctx))
		return 0;

	if (split_path_parameter(full_path, path, name) == -1)
		return 0;

	cwmp_debug(1, "scal", "Object '%s' parameter '%s' get value '%s'\n",
		   path, name, value);

	cwmp_path_to_array(&ctx->buf, path);
	blobmsg_add_string(&ctx->buf, "name", name);
	blobmsg_add_string(&ctx->buf, "value", value);
	err = ubus_invoke(ctx->ubus_ctx, ctx->scald_id, "set",
			ctx->buf.head, scal_set_cb, &ret, 1000);
	if (err) {
		err_ubus(err, "ubus_invoke %s->%s %s=%s",
			ctx->ubus_path, "set", full_path, value);
		ctx->prepared = 0;
		ret = -1;
	}
	return ret;
}

static int scal_generic_call(struct scal_ctx *ctx, const char *method)
{
	int err;
	int ret = 0;

	if (!scal_ctx_prepare(ctx))
		return -1;

	err = ubus_invoke(ctx->ubus_ctx, ctx->scald_id, method,
				NULL, scal_set_cb, &ret, 1000);
	if (err) {
		err_ubus(err, "ubus_invoke %s %s", ctx->ubus_path, method);
		ctx->prepared = 0;
		return -1;
	}
	return ret;
}

static int scal_commit()
{
	int rc = scal_generic_call(&scal, "validate");

	if (rc != -1)
		rc = scal_generic_call(&scal, "commit");

	return rc;
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

static void scal_partial_path_format(char *path)
{
	const unsigned len = strlen(path);

	if (len == 0)
		return;

	if (path[len - 1] == '.')
		path[len - 1] = 0;
}

static int get_parameter_values(struct cwmp_iterator *it)
{
	struct blob_attr *params = NULL;
	int rc = 0;
	int rem;
	unsigned len;
	bool multi_inst_obj = false;

	scal_partial_path_format((char *)it->path);
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

static int scal_get_parameter_names(struct cwmp_iterator *it, bool nxt_lvl)
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

static int scal_set_parameter_value(const char *path, const char *value)
{
	return scal_set(&scal, path, value);
}

static int scal_get_parameter_value(struct cwmp_iterator *it, bool nxt_lvl)
{
	int rc;

	if (nxt_lvl)
		rc = get_parameter_values(it);
	else
		rc = scal_get(&scal, it);

	return rc;
}

static void scal_get_parameter_values_init()
{
}

const struct backend backend = {
	.init = scal_init,
	.deinit = scal_deinit,
	.get_parameter_names = scal_get_parameter_names,
	.get_parameter_value = scal_get_parameter_value,
	.set_parameter_value = scal_set_parameter_value,
	.get_parameter_values_init = scal_get_parameter_values_init,
	.commit = scal_commit,
};
