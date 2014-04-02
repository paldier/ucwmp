#include <libubus.h>

#include "state.h"

static struct ubus_context *ctx;
static struct blob_buf b;

static int
cwmp_connection_request(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	cwmp_flag_event("6 CONNECTION REQUEST", NULL);
	return 0;
}

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

static const struct blobmsg_policy info_policy[__SERVER_INFO_MAX] = {
	[SERVER_INFO_URL] = { .name = "url", .type = BLOBMSG_TYPE_STRING },
	[SERVER_INFO_USERNAME] = { .name = "username", .type = BLOBMSG_TYPE_STRING },
	[SERVER_INFO_PASSWORD] = { .name = "password", .type = BLOBMSG_TYPE_STRING },
	[SERVER_INFO_PERIODIC_INTERVAL] = { .name = "periodic_interval", .type = BLOBMSG_TYPE_INT32 },
	[SERVER_INFO_PERIODIC_ENABLED] = { .name = "periodic_enabled", .type = BLOBMSG_TYPE_BOOL },
};

static int
cwmp_server_info_get(struct ubus_context *ctx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg)
{
	blob_buf_init(&b, 0);

	if (config.acs_info[0])
		blobmsg_add_string(&b, "url", config.acs_info[0]);
	if (config.acs_info[1])
		blobmsg_add_string(&b, "username", config.acs_info[1]);
	if (config.acs_info[2])
		blobmsg_add_string(&b, "password", config.acs_info[2]);

	blobmsg_add_u8(&b, "periodic_enabled", config.periodic_enabled);
	blobmsg_add_u32(&b, "periodic_interval", config.periodic_interval);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static void cwmp_server_info_set_url(struct blob_attr **tb)
{
	int i;

	for (i = SERVER_INFO_URL; i <= SERVER_INFO_PASSWORD; i++)
		config.acs_info[i - SERVER_INFO_URL] =
			tb[i] ? blobmsg_data(tb[i]) : NULL;

	cwmp_update_config(CONFIG_CHANGE_ACS_INFO);
}


static void cwmp_server_info_set_periodic(struct blob_attr **tb)
{
	struct blob_attr *cur;

	if ((cur = tb[SERVER_INFO_PERIODIC_INTERVAL]))
		config.periodic_interval = blobmsg_get_u32(cur);

	if ((cur = tb[SERVER_INFO_PERIODIC_ENABLED]))
		config.periodic_enabled = blobmsg_get_bool(cur);

	cwmp_update_config(CONFIG_CHANGE_PERIODIC_INFO);
}

static int
cwmp_server_info_set(struct ubus_context *ctx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg)
{
	struct blob_attr *tb[__SERVER_INFO_MAX];

	blobmsg_parse(info_policy, __SERVER_INFO_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[SERVER_INFO_URL])
		cwmp_server_info_set_url(tb);

	if (tb[SERVER_INFO_PERIODIC_INTERVAL] || tb[SERVER_INFO_PERIODIC_ENABLED])
		cwmp_server_info_set_periodic(tb);

	return 0;
}

static struct ubus_method cwmp_methods[] = {
	UBUS_METHOD_NOARG("server_info_get", cwmp_server_info_get ),
	UBUS_METHOD("server_info_set", cwmp_server_info_set, info_policy ),

	UBUS_METHOD_NOARG("connection_request", cwmp_connection_request ),
	UBUS_METHOD_NOARG("event_sent", cwmp_event_sent),
	UBUS_METHOD("event_add", cwmp_event_add, event_policy ),
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
