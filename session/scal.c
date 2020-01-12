#include "scal.h"

#include <inttypes.h>

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

int scal_info(struct scal_ctx *ctx, const char *path,
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

int scal_list(struct scal_ctx *ctx, const char *path, struct blob_attr **objs)
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


static const char * blob_any_to_string(struct blob_attr *val,
					char *buf, unsigned len)
{
	const enum blobmsg_type t = blobmsg_type(val);

	switch (t) {
	case BLOBMSG_TYPE_STRING:
		buf = blobmsg_data(val);
		break;
	case BLOBMSG_TYPE_INT32:
		snprintf(buf, len, "%d", blobmsg_get_u32(val));
		break;
	case BLOBMSG_TYPE_INT64:
		snprintf(buf, len, "%"PRId64, blobmsg_get_u64(val));
		break;
	case BLOBMSG_TYPE_BOOL:
		buf = blobmsg_get_bool(val) ? "true" : "false";
		break;
	default:
		err("unknown type %d\n", t);
		break;
	}
	return buf;
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

int scal_get(struct scal_ctx *ctx, struct cwmp_iterator *it)
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

int scal_set(struct scal_ctx *ctx, const char *full_path, const char *value)
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

int scal_validate(struct scal_ctx *ctx)
{
	return scal_generic_call(ctx, "validate");
}

int scal_commit(struct scal_ctx *ctx)
{
	return scal_generic_call(ctx, "commit");
}

