#ifndef	CWMP_SCAL_H
#define	CWMP_SCAL_H

#include "backend.h"

#include <string.h>
#include <libubus.h>
#include <libubox/blobmsg.h>

struct scal_ctx {
	char ubus_path[32];
	struct ubus_context *ubus_ctx;
	unsigned scald_id;
	int prepared;
	struct blob_buf buf;
};


static inline void scal_init(struct scal_ctx *ctx,
			struct ubus_context *ubus)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->ubus_ctx = ubus;
}

static inline void scal_set_module(struct scal_ctx *ctx, const char *mod)
{
	sprintf(ctx->ubus_path, "scald.%s", mod);
	ctx->prepared = 0;
}

static inline void scal_deinit(struct scal_ctx *ctx)
{
	blob_buf_free(&ctx->buf);
}

#if 0
int scal_param_get(struct scal_ctx *ctx,
			const char *path,
			const char *name,
			struct blob_attr **attr);
int scal_param_set(struct scal_ctx *ctx,
			const char *path,
			const char *name,
			const char *value);
#endif

int scal_validate(struct scal_ctx *ctx);
int scal_commit(struct scal_ctx *ctx);
int scal_list(struct scal_ctx *ctx, const char *path, struct blob_attr **objs);
int scal_info(struct scal_ctx *ctx, const char *path,
		struct blob_attr **params, bool *multi_inst);
int scal_get(struct scal_ctx *ctx, struct cwmp_iterator *it);
int scal_set(struct scal_ctx *ctx, const char *full_path, const char *value);

#endif
