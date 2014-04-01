#include <libubus.h>

#include "state.h"

static struct ubus_context *ctx;


static int
cwmp_event_sent(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	cwmp_clear_pending_events();
	return 0;
}

static const struct blobmsg_policy event_policy[] = {
	{ .name = "event", .type = BLOBMSG_TYPE_STRING },
	{ .name = "commandkey", .type = BLOBMSG_TYPE_STRING },
};

static int
cwmp_event_add(struct ubus_context *ctx, struct ubus_object *obj,
	       struct ubus_request_data *req, const char *method,
	       struct blob_attr *msg)
{
	struct blob_attr *tb[2];
	const char *id, *ckey = NULL;

	blobmsg_parse(event_policy, 2, tb, blob_data(msg), blob_len(msg));
	if (!tb[0])
		return UBUS_STATUS_INVALID_ARGUMENT;

	id = blobmsg_data(tb[0]);
	if (tb[1])
		ckey = blobmsg_data(tb[1]);

	cwmp_flag_event(id, ckey);
	return 0;
}

static const struct blobmsg_policy acs_policy[] = {
	{ .name = "url", .type = BLOBMSG_TYPE_STRING },
	{ .name = "username", .type = BLOBMSG_TYPE_STRING },
	{ .name = "password", .type = BLOBMSG_TYPE_STRING },
};

static int
cwmp_acs_set_url(struct ubus_context *ctx, struct ubus_object *obj,
	         struct ubus_request_data *req, const char *method,
	         struct blob_attr *msg)
{
	struct blob_attr *tb[3];
	char *url[3];
	int i;

	blobmsg_parse(acs_policy, ARRAY_SIZE(acs_policy), tb, blob_data(msg), blob_len(msg));
	if (!tb[0])
		return UBUS_STATUS_INVALID_ARGUMENT;

	for (i = 0; i < ARRAY_SIZE(url); i++)
		url[i] = tb[i] ? blobmsg_data(tb[i]) : NULL;

	if (cwmp_set_acs_config(url))
		return UBUS_STATUS_INVALID_ARGUMENT;

	return 0;
}

static struct ubus_method cwmp_methods[] = {
	UBUS_METHOD_NOARG("event_sent", cwmp_event_sent),
	UBUS_METHOD("event_add", cwmp_event_add, event_policy ),
	UBUS_METHOD("acs_set_url", cwmp_acs_set_url, acs_policy ),
};

static struct ubus_object_type cwmp_object_type =
	UBUS_OBJECT_TYPE("cwmp", cwmp_methods);

static struct ubus_object cwmp_object = {
	.name = "cwmp",
	.type = &cwmp_object_type,
	.methods = cwmp_methods,
	.n_methods = ARRAY_SIZE(cwmp_methods),
};

int cwmp_ubus_register(void)
{
	ctx = ubus_connect(NULL);
	if (!ctx)
		return -1;

	if (ubus_add_object(ctx, &cwmp_object))
		return -1;

	ubus_add_uloop(ctx);
	return 0;
}
