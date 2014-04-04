#include <string.h>
#include <time.h>

#include <libubox/utils.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "session-soap.h"
#include "session-rpc.h"
#include "session-attr.h"
#include "object.h"

struct blob_buf events;

static node_t *cwmp_open_array(node_t *node, const char *name)
{
	return roxml_add_node(node, 0, ROXML_ELM_NODE, (char *) name, NULL);
}

static void cwmp_close_array(node_t *node, int n_values, const char *type)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "%s[%u]", type, n_values);
	roxml_add_node(node, 0, ROXML_ATTR_NODE, "soap-enc:arrayType", buf);
}

void cwmp_add_parameter_value_struct(node_t *node, const char *name, const char *value, const char *type)
{
	struct xml_kv kv[2] = {
		{ "Name", name },
		{ "Value", value },
	};
	node_t *nodes[2];

	node = roxml_add_node(node, 0, ROXML_ELM_NODE, "ParameterValueStruct", NULL);
	xml_add_multi(node, ROXML_ELM_NODE, ARRAY_SIZE(kv), kv, nodes);
	if (!type)
		type = "xsd:string";

	roxml_add_node(nodes[1], 0, ROXML_ATTR_NODE, "xsi:type", (char *) type);
}

static int cwmp_add_obj_parameter_value(struct path_iterate *it, struct cwmp_object *obj, int i)
{
	const char *value, *type = NULL;

	if (!obj->get_param)
		return 0;

	if (obj->get_param(obj, i, &value))
		return 0;

	if (!value)
		value = "";

	if (obj->param_types)
		type = obj->param_types[i];

	cwmp_add_parameter_value_struct(it->node, it->path, value, type);
	return 1;
}

static int cwmp_add_parameter_value(node_t *node, const char *name)
{
	struct path_iterate it = {
		.node = node,
		.cb = cwmp_add_obj_parameter_value,
	};

	strncpy(it.path, name, sizeof(it.path));
	return cwmp_path_iterate(&it, false);
}

static int cwmp_handle_get_parameter_values(struct rpc_data *data)
{
	node_t *node, *cur_node;
	char *cur = NULL;
	int n_values = 0;

	node = roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:GetParameterValuesResponse", NULL);
	node = cwmp_open_array(node, "ParameterList");

	cur_node = soap_array_start(data->in, "ParameterNames", NULL);
	if (!cur_node)
		return CWMP_ERROR_INVALID_PARAM;

	while (soap_array_iterate_contents(&cur_node, "string", &cur))
		n_values += cwmp_add_parameter_value(node, cur);

	cwmp_close_array(node, n_values, "cwmp:ParameterValueStruct");

	return 0;
}

static int cwmp_handle_set_parameter_values(struct rpc_data *data)
{
	char *name = NULL, *value = NULL, *type = NULL;
	node_t *node, *cur_node;
	struct {
		char *param;
		int code;
	} *fault;
	int n_fault = 0, len;
	int error = 0;
	int i;

	cur_node = soap_array_start(data->in, "ParameterList", &len);
	if (!cur_node)
		return CWMP_ERROR_INVALID_PARAM;

	fault = alloca(len * sizeof(*fault));
	while (soap_array_iterate(&cur_node, "ParameterValueStruct", &node)) {
		bool abort = false;
		int error;

		name = soap_get_field(node, "Name");
		node = roxml_get_chld(node, "Value", 0);
		if (node) {
			value = roxml_get_content(node, NULL, 0, NULL);
			node = roxml_get_attr(node, "type", 0);
			if (node)
				type = roxml_get_content(node, NULL, 0, NULL);
		}

		if (!name || !value) {
			abort = true;
		} else {
			error = cwmp_param_set(name, value);
			if (error) {
				fault[n_fault].param = name;
				fault[n_fault].code = error;
				n_fault++;
				name = NULL;
			}
		}

		roxml_release(name);
		roxml_release(value);
		roxml_release(type);
		name = value = type = NULL;

		if (abort) {
			error = CWMP_ERROR_INVALID_PARAM;
			break;
		}
	}

	cwmp_commit(!n_fault && !error);

	if (error)
		goto out;

	if (!n_fault) {
		node = roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:SetParameterValuesResponse", NULL);
		node = roxml_add_node(node, 0, ROXML_ELM_NODE, "Status", "0");
		goto out;
	}

	node = soap_add_fault(data->out, CMWP_ERROR_INVALID_PARAM_VAL);
	for (i = 0; i < n_fault; i++) {
		node_t *f = roxml_add_node(node, 0, ROXML_ELM_NODE, "SetParameterValuesFault", NULL);
		roxml_add_node(f, 0, ROXML_ELM_NODE, "ParameterName", fault[i].param);
		soap_add_fault_struct(f, fault[i].code);
	}

out:
	for (i = 0; i < n_fault; i++)
		roxml_release(fault[i].param);

	return error;
}

static void cwmp_add_object_path(node_t *node, char *path, bool writable)
{
	node = roxml_add_node(node, 0, ROXML_ELM_NODE, "ParameterInfoStruct", NULL);
	roxml_add_node(node, 0, ROXML_ELM_NODE, "Name", path);
	roxml_add_node(node, 0, ROXML_ELM_NODE, "Writable", writable ? "1" : "0");
}

static int cwmp_add_object_param(struct path_iterate *it, struct cwmp_object *obj, int idx)
{
	bool writable = false;

	if (idx >= 0)
		writable = cwmp_object_param_writable(obj, idx);

	cwmp_add_object_path(it->node, it->path, writable);
	return 1;
}

static int cwmp_handle_get_parameter_names(struct rpc_data *data)
{
	struct path_iterate it = {
		.cb = cwmp_add_object_param
	};
	bool next_level = false;
	node_t *node;
	int n_params;

	node = data->in;
	if (soap_get_boolean_field(node, "NextLevel", &next_level))
		return CWMP_ERROR_INVALID_ARGUMENTS;

	if (!__soap_get_field(node, "ParameterPath", it.path, sizeof(it.path)))
		return CWMP_ERROR_INVALID_ARGUMENTS;

	node = roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:GetParameterNamesResponse", NULL);

	it.node = cwmp_open_array(node, "ParameterList");
	n_params = cwmp_path_iterate(&it, next_level);
	cwmp_close_array(it.node, n_params, "cwmp:ParameterInfoStruct");

	if (it.error) {
		roxml_del_node(node);
		return it.error;
	}

	return 0;
}

static int cwmp_handle_get_parameter_attributes(struct rpc_data *data)
{
	return CWMP_ERROR_REQUEST_DENIED;
}

static int cwmp_set_param_attr(node_t *node)
{
	struct param_attr *attr;
	char buf[CWMP_PATH_LEN];
	bool val;

	if (!__soap_get_field(node, "Name", buf, sizeof(buf)))
		return CWMP_ERROR_INVALID_PARAM;

	attr = cwmp_attr_cache_get(buf);
	if (!attr)
		return CWMP_ERROR_INVALID_PARAM;

	if (!soap_get_boolean_field(node, "NotificationChange", &val) && val) {
		int intval;

		if (soap_get_int_field(node, "Notification", &intval))
			return CWMP_ERROR_INVALID_PARAM;

		if (intval > 6)
			return CMWP_ERROR_INVALID_PARAM_VAL;

		attr->notification = intval;
	}

	if (!soap_get_boolean_field(node, "AccessListChange", &val) && val) {
		char *str;
		node_t *cur;

		attr->acl_subscriber = false;

		cur = soap_array_start(node, "AccessList", NULL);
		while (soap_array_iterate_contents(&cur, "string", &str)) {
			if (!strcmp(str, "Subscriber"))
				attr->acl_subscriber = true;
		}
	}

	return 0;
}

static int cwmp_handle_set_parameter_attributes(struct rpc_data *data)
{
	node_t *node, *cur_node;
	int ret;

	cur_node = soap_array_start(data->in, "ParameterList", NULL);
	if (!cur_node)
		return CWMP_ERROR_INVALID_PARAM;

	while (soap_array_iterate(&cur_node, "SetParameterAttributesStruct", &node)) {
		ret = cwmp_set_param_attr(node);
		if (ret) {
			/* discard any changes and reload the attribute cache */
			cwmp_attr_cache_load();
			break;
		}
	}

	if (!ret)
		cwmp_attr_cache_save();

	return ret;
}

static int cwmp_handle_add_object(struct rpc_data *data)
{
	return CWMP_ERROR_REQUEST_DENIED;
}

static int cwmp_handle_delete_object(struct rpc_data *data)
{
	return CWMP_ERROR_REQUEST_DENIED;
}

static int cwmp_handle_factory_reset(struct rpc_data *data)
{
	roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:FactoryResetResponse", NULL);
	return 0;
}

static int cwmp_handle_reboot(struct rpc_data *data)
{
	roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:RebootResponse", NULL);
	return 0;
}

static int cwmp_handle_download(struct rpc_data *data)
{
	return CWMP_ERROR_REQUEST_DENIED;
}

static int cwmp_handle_get_rpc_methods(struct rpc_data *data);

static const struct rpc_method rpc_methods[] = {
	{ "GetRPCMethods", cwmp_handle_get_rpc_methods },
	{ "GetParameterValues", cwmp_handle_get_parameter_values },
	{ "SetParameterValues", cwmp_handle_set_parameter_values },
	{ "GetParameterNames", cwmp_handle_get_parameter_names },
	{ "GetParameterAttributes", cwmp_handle_get_parameter_attributes },
	{ "SetParameterAttributes", cwmp_handle_set_parameter_attributes },
	{ "AddObject", cwmp_handle_add_object },
	{ "DeleteObject", cwmp_handle_delete_object },
	{ "Reboot", cwmp_handle_reboot },
	{ "Download", cwmp_handle_download },
	{ "FactoryReset", cwmp_handle_factory_reset },
};

static int cwmp_handle_get_rpc_methods(struct rpc_data *data)
{
	node_t *node;
	int i;

	node = roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:GetRPCMethodsResponse", NULL);

	node = cwmp_open_array(node, "MethodList");
	for (i = 0; i < ARRAY_SIZE(rpc_methods); i++)
		roxml_add_node(node, 0, ROXML_ELM_NODE, "string", (char *) rpc_methods[i].name);
	cwmp_close_array(node, ARRAY_SIZE(rpc_methods), "xsd:string");

	return 0;
}

static int cwmp_inform_response(struct rpc_data *data)
{
	cwmp_clear_pending_events();
	return 0;
}

static int cwmp_ignore_response(struct rpc_data *data)
{
	return 0;
}

static const struct rpc_method response_types[] = {
	{ "InformResponse", cwmp_inform_response },
	{ "TransferCompleteResponse", cwmp_ignore_response },
};

int cwmp_session_response(struct rpc_data *data)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(rpc_methods); i++) {
		if (strcmp(rpc_methods[i].name, data->method) != 0)
			continue;

		data->response = SOAP_RESPONSE_DATA;
		return rpc_methods[i].handler(data);
	}

	for (i = 0; i < ARRAY_SIZE(response_types); i++) {
		if (strcmp(response_types[i].name, data->method) != 0)
			continue;

		return response_types[i].handler(data);
	}

	return CWMP_ERROR_INVALID_METHOD;
}

static void cwmp_add_inform_parameters(node_t *node)
{
	static const char *devinfo_params[] = {
		"SpecVersion",
		"HardwareVersion",
		"SoftwareVersion",
		"ProvisioningCode",
	};
	static const char *mgmt_params[] = {
		"ConnectionRequestURL",
		"ParameterKey",
	};
	char path[CWMP_PATH_LEN];
	char *cur, *cur1;
	int i, n = 0;

	node = cwmp_open_array(node, "ParameterList");

	cur = path + sprintf(path, "%s.", cwmp_object_name(&root_object));

	strcpy(cur, "DeviceSummary");
	n += cwmp_add_parameter_value(node, path);

	cur1 = cur + sprintf(cur, "DeviceInfo.");
	for (i = 0; i < ARRAY_SIZE(devinfo_params); i++) {
		strcpy(cur1, devinfo_params[i]);
		n += cwmp_add_parameter_value(node, path);
	}

	cur1 = cur + sprintf(cur, "ManagementServer.");
	for (i = 0; i < ARRAY_SIZE(mgmt_params); i++) {
		strcpy(cur1, mgmt_params[i]);
		n += cwmp_add_parameter_value(node, path);
	}

	n += cwmp_attr_cache_add_changed(node);

	cwmp_close_array(node, n, "ParameterValueStruct");
}

static int cwmp_add_event(node_t *node, const char *code, const char *key)
{
	struct xml_kv ev_kv[2] = {
		{ "EventCode", code },
		{ "CommandKey", key },
	};

	node = roxml_add_node(node, 0, ROXML_ELM_NODE, "EventStruct", NULL);
	xml_add_multi(node, ROXML_ELM_NODE, ARRAY_SIZE(ev_kv), ev_kv, NULL);
	return 1;
}

static int cwmp_add_event_blob(node_t *node, struct blob_attr *ev)
{
	static const struct blobmsg_policy ev_policy[2] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *ev_attr[2];
	const char *val = "";

	if (blobmsg_type(ev) != BLOBMSG_TYPE_ARRAY)
		return 0;

	blobmsg_parse_array(ev_policy, ARRAY_SIZE(ev_policy), ev_attr,
			    blobmsg_data(ev), blobmsg_data_len(ev));
	if (!ev_attr[0])
		return 0;

	if (ev_attr[1])
		val = blobmsg_data(ev_attr[1]);

	return cwmp_add_event(node, blobmsg_data(ev_attr[0]), val);
}

static void cwmp_add_inform_events(node_t *node, bool changed)
{
	struct blob_attr *ev = NULL;
	int n = 0;

	node = cwmp_open_array(node, "Event");

	if (events.head) {
		struct blob_attr *cur;
		int rem;

		ev = blob_data(events.head);
		blobmsg_for_each_attr(cur, ev, rem)
			n += cwmp_add_event_blob(node, cur);
	}

	if (changed)
		n += cwmp_add_event(node, "4 VALUE CHANGED", "");

	cwmp_close_array(node, n, "EventStruct");
}

int cwmp_session_init(struct rpc_data *data)
{
	time_t now = time(NULL);
	node_t *node;
	bool changed;

	changed = cwmp_attr_cache_load();
	node = roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:Inform", NULL);

	roxml_add_node(node, 0, ROXML_ELM_NODE, "MaxEnvelopes", "1");
	roxml_add_node(node, 0, ROXML_ELM_NODE, "RetryCount", "0");
	soap_add_time(node, "CurrentTime", localtime(&now));
	cwmp_add_device_id(node);
	cwmp_add_inform_parameters(node);
	cwmp_add_inform_events(node, changed);

	return 0;
}

void cwmp_session_continue(struct rpc_data *data)
{
	if (data->empty_message) {
		uloop_end();
		return;
	}

	data->response = SOAP_RESPONSE_EMPTY;
}
