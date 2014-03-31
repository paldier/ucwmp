#include <libubox/utils.h>
#include <libubox/blobmsg_json.h>

#include "session-soap.h"
#include "session-rpc.h"
#include "object.h"
#include "util.h"

enum {
	SERVER_PARAM_URL,
	SERVER_PARAM_USERNAME,
	SERVER_PARAM_PASSWORD,
	__SERVER_PARAM_MAX
};

static char *server_params[__SERVER_PARAM_MAX];

static const char *server_param_names[__SERVER_PARAM_MAX] = {
	[SERVER_PARAM_URL] = "URL",
	[SERVER_PARAM_USERNAME] = "Username",
	[SERVER_PARAM_PASSWORD] = "Password",
};

static int server_commit(struct cwmp_object *obj)
{
	const char *username = server_params[SERVER_PARAM_USERNAME];
	const char *password = server_params[SERVER_PARAM_PASSWORD];
	const char *url = server_params[SERVER_PARAM_URL];
	char *auth_str = NULL;
	int len;

	if (!url)
		return -1;

	if (!username) {
		cwmp_update_url(url, NULL);
		return 0;
	}

	if (!password) {
		cwmp_update_url(url, username);
		return 0;
	}

	len = strlen(username) + strlen(password) + 2;
	if (len > 512)
		return -1;

	auth_str = alloca(len);
	sprintf(auth_str, "%s:%s", username, password);
	cwmp_update_url(url, auth_str);
	return 0;
}

static unsigned long server_writable = (1 << __SERVER_PARAM_MAX) - 1;

static struct cwmp_object server_object = {
	.params = server_param_names,
	.values = server_params,
	.n_params = __SERVER_PARAM_MAX,
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
	cwmp_object_add(&server_object, "ManagementServer", NULL);
	cwmp_object_add(&devinfo_object, "DeviceInfo", NULL);
}
