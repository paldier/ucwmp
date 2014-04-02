#include <libubox/utils.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "session-soap.h"
#include "session-rpc.h"
#include "object.h"
#include "util.h"

static struct ubus_context *ubus_ctx;
static uint32_t cwmp_id;
static struct blob_buf b;

enum {
	MGMT_ATTR_URL,
	MGMT_ATTR_USERNAME,
	MGMT_ATTR_PASSWORD,
	__MGMT_ATTR_MAX,
};

static char *server_values[__MGMT_ATTR_MAX];
static const char * const server_params[__MGMT_ATTR_MAX] = {
	[MGMT_ATTR_URL] = "URL",
	[MGMT_ATTR_USERNAME] = "Username",
	[MGMT_ATTR_PASSWORD] = "Password",
};

static void server_receive_values(struct ubus_request *req, int type, struct blob_attr *msg)
{
	static const struct blobmsg_policy policy[__MGMT_ATTR_MAX] = {
		[MGMT_ATTR_URL] = { .name = "url", .type = BLOBMSG_TYPE_STRING },
		[MGMT_ATTR_USERNAME] = { .name = "username", .type = BLOBMSG_TYPE_STRING },
		[MGMT_ATTR_PASSWORD] = { .name = "password", .type = BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[__MGMT_ATTR_MAX];
	int i;

	blobmsg_parse(policy, ARRAY_SIZE(policy), tb, blob_data(msg), blob_len(msg));
	for (i = 0; i < __MGMT_ATTR_MAX; i++) {
		free(server_values[i]);
		server_values[i] = tb[i] ? strdup(blobmsg_data(tb[i])) : NULL;
	}
}

static void server_load_values(void)
{
	ubus_invoke(ubus_ctx, cwmp_id, "server_info_get", b.head,
		    server_receive_values, NULL, 0);
}


static int server_commit(struct cwmp_object *obj)
{
	int i;

	blob_buf_init(&b, 0);
	for (i = 0; i < ARRAY_SIZE(server_params); i++) {
		if (!server_values[i])
			continue;

		blobmsg_add_string(&b, server_params[i], server_values[i]);
	}

	ubus_invoke(ubus_ctx, cwmp_id, "server_info_set", b.head, NULL, NULL, 0);
	return 0;
}

static unsigned long server_writable = (1 << ARRAY_SIZE(server_params)) - 1;

static struct cwmp_object server_object = {
	.params = server_params,
	.values = server_values,
	.n_params = ARRAY_SIZE(server_params),
	.writable = &server_writable,
	.commit = server_commit,
};

#define devinfo_main_fields(t, p) \
	_v(t, p, Manufacturer) \
	_v(t, p, ManufacturerOUI) \
	_v(t, p, ModelName) \
	_v(t, p, Description) \
	_v(t, p, ProductClass) \
	_v(t, p, SerialNumber) \
	_v(t, p, HardwareVersion) \
	_v(t, p, SoftwareVersion) \
	_v(t, p, ModemFirmwareVersion) \
	_v(t, p, AdditionalHardwareVersion) \
	_v(t, p, AdditionalSoftwareVersion) \

#define devinfo_extra_fields(t, p) \
	_v(t, p, SpecVersion)

#define devinfo_fields(t, p) \
	devinfo_main_fields(t, p) \
	devinfo_extra_fields(t, p)

enum devinfo_fields {
	CWMP_ENUM(DEVINFO, devinfo_fields)
	__DEVINFO_MAX
};

static const char *devinfo_param_names[__DEVINFO_MAX] = {
	CWMP_PARAM_NAMES(DEVINFO, devinfo_fields)
};

static char *devinfo_values[__DEVINFO_MAX];

static struct cwmp_object devinfo_object = {
	.params = devinfo_param_names,
	.values = devinfo_values,
	.n_params = __DEVINFO_MAX,
};

void server_load_info(const char *filename)
{
	static const struct blobmsg_policy devinfo_policy[__DEVINFO_MAX] = {
		CWMP_BLOBMSG_STRING(DEVINFO, devinfo_main_fields)
	};
	struct blob_attr *tb[__DEVINFO_MAX];
	static struct blob_buf b;
	int i;

	memset(devinfo_values, 0, sizeof(devinfo_values));

	blob_buf_init(&b, 0);
	blobmsg_add_json_from_file(&b, filename);
	blobmsg_parse(devinfo_policy, __DEVINFO_MAX, tb, blob_data(b.head), blob_len(b.head));

	for (i = 0; i < __DEVINFO_MAX; i++) {
		if (!tb[i])
			continue;

		devinfo_values[i] = blobmsg_data(tb[i]);
	}
}

void cwmp_clear_pending_events(void)
{
	blob_buf_init(&b, 0);
	ubus_invoke(ubus_ctx, cwmp_id, "event_sent", b.head, NULL, NULL, 0);
}

void cwmp_add_device_id(node_t *node)
{
	struct xml_kv kv[] = {
		{ "Manufacturer", devinfo_values[DEVINFO_Manufacturer] },
		{ "OUI", devinfo_values[DEVINFO_ManufacturerOUI] },
		{ "ProductClass", devinfo_values[DEVINFO_ProductClass] },
		{ "SerialNumber", devinfo_values[DEVINFO_SerialNumber] },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(kv); i++)
		if (!kv[i].value)
			kv[i].value = "(unknown)";

	node = roxml_add_node(node, 0, ROXML_ELM_NODE, "DeviceId", NULL);
	xml_add_multi(node, ROXML_ELM_NODE, ARRAY_SIZE(kv), kv, NULL);
}

static void __constructor server_init(void)
{
	ubus_ctx = ubus_connect(NULL);
	ubus_lookup_id(ubus_ctx, "cwmp", &cwmp_id);
	server_load_values();

	cwmp_object_add(&server_object, "ManagementServer", NULL);
	cwmp_object_add(&devinfo_object, "DeviceInfo", NULL);
}
