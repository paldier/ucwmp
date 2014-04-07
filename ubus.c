#include <time.h>

#include <libubox/uclient.h>
#include <libubox/uclient-utils.h>
#include <libubus.h>

#include "state.h"

static struct ubus_context *ctx;
static struct blob_buf b;
static char auth_md5[33];

static const char * const auth_realm = "ucwmp";

enum {
	CONN_REQ_USERNAME,
	CONN_REQ_REALM,
	CONN_REQ_NONCE,
	CONN_REQ_URI,
	CONN_REQ_RESPONSE,
	CONN_REQ_CNONCE,
	CONN_REQ_NC,
	__CONN_REQ_MAX,
};

static const struct blobmsg_policy conn_req_policy[__CONN_REQ_MAX] = {
	[CONN_REQ_USERNAME] = { "username", BLOBMSG_TYPE_STRING },
	[CONN_REQ_REALM] = { "realm", BLOBMSG_TYPE_STRING },
	[CONN_REQ_NONCE] = { "nonce", BLOBMSG_TYPE_STRING },
	[CONN_REQ_URI] = { "uri", BLOBMSG_TYPE_STRING },
	[CONN_REQ_RESPONSE] = { "response", BLOBMSG_TYPE_STRING },
	[CONN_REQ_CNONCE] = { "cnonce", BLOBMSG_TYPE_STRING },
	[CONN_REQ_NC] = { "nc", BLOBMSG_TYPE_STRING },
};

static void conn_req_challenge(void)
{
	time_t cur = time(NULL);
	char nonce[9];

	snprintf(nonce, sizeof(nonce), "%08x", (uint32_t) cur);
	blobmsg_add_string(&b, "nonce", nonce);
	blobmsg_add_string(&b, "realm", auth_realm);
}

static bool conn_req_check_digest(struct blob_attr **tb)
{
	struct http_digest_data data = {
		.uri = blobmsg_data(tb[CONN_REQ_URI]),
		.method = "GET",
		.auth_hash = auth_md5,
		.qop = "auth",
		.nc = blobmsg_data(tb[CONN_REQ_NC]),
		.nonce = blobmsg_data(tb[CONN_REQ_NONCE]),
		.cnonce = blobmsg_data(tb[CONN_REQ_CNONCE]),
	};
	char md5[33];

	http_digest_calculate_response(md5, &data);

	return !strcmp(blobmsg_data(tb[CONN_REQ_RESPONSE]), md5);
}

static bool conn_req_validate(struct blob_attr **tb)
{
	int i;

	if (!config.local_username || !config.local_password)
		return false;

	http_digest_calculate_auth_hash(auth_md5, config.local_username,
					auth_realm, config.local_password);

	for (i = 0; i < __CONN_REQ_MAX; i++) {
		if (!tb[i])
			return false;
	}

	return conn_req_check_digest(tb);
}

static int
cwmp_connection_request(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__CONN_REQ_MAX];
	bool ok;

	blob_buf_init(&b, 0);

	blobmsg_parse(conn_req_policy, __CONN_REQ_MAX, tb, blob_data(msg), blob_len(msg));

	ok = conn_req_validate(tb);
	conn_req_challenge();
	blobmsg_add_u8(&b, "ok", ok);

	if (ok)
		cwmp_flag_event("6 CONNECTION REQUEST", NULL);

	ubus_send_reply(ctx, req, b.head);

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
	[SERVER_INFO_LOCAL_USERNAME] = { .name = "local_username", .type = BLOBMSG_TYPE_STRING },
	[SERVER_INFO_LOCAL_PASSWORD] = { .name = "local_password", .type = BLOBMSG_TYPE_STRING },
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
	blobmsg_add_u32(&b, "connection_port", config.conn_req_port);

	if (config.local_username)
		blobmsg_add_string(&b, "local_username", config.local_username);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static bool cwmp_server_info_set_url(struct blob_attr **tb)
{
	bool changed = false;
	int i;

	for (i = SERVER_INFO_URL; i <= SERVER_INFO_PASSWORD; i++) {
		const char *old = config.acs_info[i - SERVER_INFO_URL];
		const char *new = tb[i] ? blobmsg_data(tb[i]) : NULL;

		config.acs_info[i - SERVER_INFO_URL] = new;

		if (!!old != !!new)
			changed = true;
		else if (old && new && strcmp(old, new) != 0)
			changed = true;
	}

	if (changed)
		cwmp_update_config(CONFIG_CHANGE_ACS_INFO);

	return changed;
}


static bool cwmp_server_info_set_periodic(struct blob_attr **tb)
{
	struct blob_attr *cur;

	if ((cur = tb[SERVER_INFO_PERIODIC_INTERVAL]))
		config.periodic_interval = blobmsg_get_u32(cur);

	if ((cur = tb[SERVER_INFO_PERIODIC_ENABLED]))
		config.periodic_enabled = blobmsg_get_bool(cur);

	cwmp_update_config(CONFIG_CHANGE_PERIODIC_INFO);
	return true;
}

static bool cwmp_server_info_set_local(struct blob_attr **tb)
{
	struct blob_attr *user, *pass;

	user = tb[SERVER_INFO_LOCAL_USERNAME];
	pass = tb[SERVER_INFO_LOCAL_PASSWORD];

	if (user)
		config.local_username = blobmsg_data(user);
	if (pass)
		config.local_password = blobmsg_data(pass);

	if (!user && !pass)
		return false;

	cwmp_update_config(CONFIG_CHANGE_LOCAL_INFO);
	return true;
}


static int
cwmp_server_info_set(struct ubus_context *ctx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg)
{
	struct blob_attr *tb[__SERVER_INFO_MAX];
	bool changed = false;

	blobmsg_parse(info_policy, __SERVER_INFO_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[SERVER_INFO_URL])
		changed |= cwmp_server_info_set_url(tb);

	if (tb[SERVER_INFO_PERIODIC_INTERVAL] || tb[SERVER_INFO_PERIODIC_ENABLED])
		changed |= cwmp_server_info_set_periodic(tb);

	changed |= cwmp_server_info_set_local(tb);

	if (changed)
		cwmp_commit_config();

	return 0;
}

static int
cwmp_session_completed(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	session_success = true;
	return 0;
}

static struct ubus_method cwmp_methods[] = {
	UBUS_METHOD_NOARG("server_info_get", cwmp_server_info_get),
	UBUS_METHOD("server_info_set", cwmp_server_info_set, info_policy),

	UBUS_METHOD_NOARG("connection_request", cwmp_connection_request),
	UBUS_METHOD_NOARG("event_sent", cwmp_event_sent),
	UBUS_METHOD("event_add", cwmp_event_add, event_policy),

	UBUS_METHOD_NOARG("session_completed", cwmp_session_completed),
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
