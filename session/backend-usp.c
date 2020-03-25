#include "backend.h"
#include "ubus.h"
#include "blob_helpers.h"

#include <string.h>
#include <inttypes.h>

#define USP_UBUS "usp.raw"

static struct uspd_ctx {
	struct ubus_context *ubus_ctx;
	unsigned uspd_id;
	int prepared;
	struct blob_buf buf;
	void *array;
} uspd;

struct uspd_get_req {
	struct cwmp_iterator *it;
	bool names_only;
	unsigned n_values;
};

struct uspd_set_req {
	const char *path;
	const char *value;
	unsigned error;
};

static void usp_init(struct ubus_context *ubus)
{
	memset(&uspd, 0, sizeof(uspd));
	uspd.ubus_ctx = ubus;
}

static void usp_deinit()
{
	blob_buf_free(&uspd.buf);
}

static int uspd_lookup(struct uspd_ctx *ctx)
{
	int err;

	err = ubus_lookup_id(ctx->ubus_ctx, USP_UBUS, &ctx->uspd_id);
	if (err)
		err_ubus(err, "ubus_lookup %s failed", USP_UBUS);

	return !err;
}

static int uspd_ctx_prepare(struct uspd_ctx *ctx)
{
	if (!ctx->prepared)
		ctx->prepared = uspd_lookup(ctx);
	return ctx->prepared;
}

static void uspd_set_req_init(struct uspd_set_req *r,
				const char *path,
				const char *value)
{
	r->path = path;
	r->value = value;
	r->error = CWMP_ERROR_INTERNAL_ERROR;
}

static void uspd_get_req_init(struct uspd_get_req *r,
				struct cwmp_iterator *it,
				int names_only)
{
	r->it = it;
	r->names_only = names_only;
	r->n_values = 0;
}

static struct blob_attr * get_parameters(struct blob_attr *msg)
{
	struct blob_attr *params = NULL;
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, msg, rem) {
		if (blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY) {
			params = cur;
			break;
		}
	}
	return params;
}

static void get_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	enum {
		P_VAL,
		P_TYPE,
		P_PARAM,
		__P_MAX
	};
	static const struct blobmsg_policy p[] = {
		{ "value", BLOBMSG_TYPE_UNSPEC },
		{ "type", BLOBMSG_TYPE_STRING },
		{ "parameter", BLOBMSG_TYPE_STRING }
	};
	char buf[32];
	struct uspd_get_req *r = req->priv;
	struct blob_attr *tb[__P_MAX];
	struct blob_attr *cur;
	struct blob_attr *params;
	int rem;

	params = get_parameters(msg);
	if (params == NULL)
		return;

	blobmsg_for_each_attr(cur, params, rem) {
		struct blob_attr *param;
		struct blob_attr *value;

		blobmsg_parse(p, __P_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		param = tb[P_PARAM];
		value = tb[P_VAL];

		if ((value && param) || (r->names_only && param)) {
			union cwmp_any u = { .param.path = r->it->path };

			u.param.path = blobmsg_get_string(param);

			if (tb[P_TYPE])
				u.param.type = blobmsg_get_string(tb[P_TYPE]);
			if (u.param.type == NULL)
				u.param.type = "xsd:string";

			u.param.value = blob_any_to_string(value, buf, sizeof(buf));
			if (u.param.value) {
				r->it->cb(r->it, &u);
				r->n_values += 1;

				cwmp_debug(1, "usp", "parameter '%s' get value '%s'\n",
		  			u.param.path, u.param.value);
			}
		} else {
			err("missing 'value' field in response for '%s'\n",
				r->it->path);
			r->it->error = CWMP_ERROR_INTERNAL_ERROR;
		}
	}
}

static void set_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	enum {
		P_STATUS,
		__P_MAX
	};
	static const struct blobmsg_policy p[] = {
		{ "status", BLOBMSG_TYPE_INT8 },
	};
	struct uspd_set_req *r = req->priv;
	struct blob_attr *tb[__P_MAX];

	blobmsg_parse(p, __P_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));
	if (tb[P_STATUS]) {
		bool status_ok = blobmsg_get_u8(tb[P_STATUS]);

		if (status_ok)
			r->error = 0;
	} else {
		err("missing 'status' field in response for set, %s = %s\n",
			r->path, r->value);
	}

	cwmp_debug(1, "usp", "parameter '%s' set value '%s' error '%d'\n",
		  r->path, r->value, r->error);
}

static int
usp_get_parameter(struct cwmp_iterator *it, bool next_level, bool names_only)
{
	struct uspd_get_req req;
	int err;

	if (!uspd_ctx_prepare(&uspd))
		return 0;

	uspd_get_req_init(&req, it, names_only);

	blob_buf_init(&uspd.buf, 0);
	blobmsg_add_string(&uspd.buf, "path", it->path);
	blobmsg_add_string(&uspd.buf, "proto", "cwmp");

	err = ubus_invoke(uspd.ubus_ctx, uspd.uspd_id, "get",
			uspd.buf.head, get_cb, &req, 10000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS " get path=%s", it->path);
		uspd.prepared = 0;
	}
	return req.n_values;
}

static void usp_get_parameter_values_init()
{
	blob_buf_init(&uspd.buf, 0);
	uspd.array = blobmsg_open_array(&uspd.buf, "paths");
}

static int usp_get_parameter_values(node_t *node, cwmp_iterator_cb cb)
{
	struct uspd_get_req req;
	struct cwmp_iterator it = { .cb = cb, .node = node };
	int err;

	blobmsg_close_array(&uspd.buf, uspd.array);

	if (!uspd_ctx_prepare(&uspd))
		return 0;

	uspd_get_req_init(&req, &it, false);

	blobmsg_add_string(&uspd.buf, "proto", "cwmp");

	err = ubus_invoke(uspd.ubus_ctx, uspd.uspd_id, "get_safe",
			uspd.buf.head, get_cb, &req, 10000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS " get_safe");
		uspd.prepared = 0;
	}
	return req.n_values;
}

static int usp_get_parameter_value(struct cwmp_iterator *it, bool next_level)
{
	blobmsg_add_string(&uspd.buf, NULL, it->path);
	return 0;
}

static int usp_get_parameter_names(struct cwmp_iterator *it, bool next_level)
{
	return usp_get_parameter(it, next_level, true);
}

static int usp_set_parameter_value(const char *path, const char *value)
{
	struct uspd_set_req req;
	int err;

	if (!uspd_ctx_prepare(&uspd))
		return CWMP_ERROR_INTERNAL_ERROR;

	uspd_set_req_init(&req, path, value);

	cwmp_debug(1, "usp", "Object '%s' set value '%s'\n",
		   path, value);

	blob_buf_init(&uspd.buf, 0);
	blobmsg_add_string(&uspd.buf, "path", path);
	blobmsg_add_string(&uspd.buf, "value", value);
	blobmsg_add_string(&uspd.buf, "proto", "cwmp");

	err = ubus_invoke(uspd.ubus_ctx, uspd.uspd_id, "set",
			uspd.buf.head, set_cb, &req, 2000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS " set path=%s,value=%s",
			path, value);
		uspd.prepared = 0;
	}
	return req.error;
}

static int usp_commit()
{
	return 0;
}

const struct backend backend = {
	.init = usp_init,
	.deinit = usp_deinit,
	.get_parameter_names = usp_get_parameter_names,
	.get_parameter_value = usp_get_parameter_value,
	.set_parameter_value = usp_set_parameter_value,
	.get_parameter_values = usp_get_parameter_values,
	.get_parameter_values_init = usp_get_parameter_values_init,
	.commit = usp_commit,
};
