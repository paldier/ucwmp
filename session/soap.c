/*
 * cwmpd - CPE WAN Management Protocol daemon
 * Copyright (C) 2014 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <libubox/utils.h>
#include <roxml.h>

#include "soap.h"
#include "rpc.h"

static int cwmp_minor_ver = 4;

void xml_add_multi(node_t *node, int type, int n_kv, const struct xml_kv *kv,
		   node_t **nodes)
{
	node_t *cur;
	int i;

	for (i = 0; i < n_kv; i++) {
		cur = roxml_add_node(node, 0, type,
				     (char *) kv[i].name,
				     (char *) kv[i].value);

		if (nodes)
			nodes[i] = cur;
	}
}

node_t *soap_add_time(node_t *node, const char *name, struct tm *val)
{
	const char *timestr = "0001-01-01T00:00:00Z";
	char buf[64];

	if (val) {
		timestr = buf;
		strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S%z", val);
	}

	return roxml_add_node(node, 0, ROXML_ELM_NODE, (char *) name, (char *) timestr);
}

static void soap_add_header_field(node_t *node, const char *name, const char *val, bool optional)
{
	node = roxml_add_node(node, 0, ROXML_ELM_NODE, (char *) name,
			      (char *) val);

	roxml_add_node(node, 0, ROXML_ATTR_NODE, "soap:mustUnderstand",
		       optional ? "0" : "1");
}

static void
soap_add_header(node_t *node, const char *id, bool inform)
{
	if (!inform && !id)
		return;

	node = roxml_add_node(node, 0, ROXML_ELM_NODE, "soap:Header", NULL);
	if (id)
		soap_add_header_field(node, "cwmp:ID", id, false);

	if (inform)
		soap_add_header_field(node, "cwmp:SupportedCWMPVersions",
				      "1.0,1.1,1.2,1.3,1.4", true);
}

static node_t *soap_msg_new(const char *id, bool inform)
{
	static char cwmp_ns[32];
	node_t *root;

	static const struct xml_kv soap_attrs[] = {
		{ "xmlns:soap", "http://schemas.xmlsoap.org/soap/envelope/" },
		{ "xmlns:soap-enc", "http://schemas.xmlsoap.org/soap/encoding/" },
		{ "xmlns:xsd", "http://www.w3.org/2001/XMLSchema" },
		{ "xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance" },
		{ "xmlns:cwmp", cwmp_ns },
	};
	int minor_ver = cwmp_minor_ver > 2 ? 2 : cwmp_minor_ver;

	snprintf(cwmp_ns, sizeof(cwmp_ns), "urn:dslforum-org:cwmp-1-%d", minor_ver);

	root = roxml_add_node(NULL, 0, ROXML_ELM_NODE, "soap:Envelope", NULL);
	xml_add_multi(root, ROXML_ATTR_NODE, ARRAY_SIZE(soap_attrs), soap_attrs, NULL);
	soap_add_header(root, id, inform);

	return roxml_add_node(root, 0, ROXML_ELM_NODE, "soap:Body", NULL);
}

void soap_add_fault_struct(node_t *node, unsigned int code)
{
	static const char *fault_msg[] = {
		"Method not supported",
		"Request denied",
		"Internal error",
		"Invalid arguments",
		"Resources exceeeded",
		"Invalid parameter name",
		"Invalid parameter type",
		"Invalid parameter value",
		"Attempt to set a non-writable parameter",
		"Notification request rejected",
		"Download failure",
		"Upload failure",
		"File transfer server authentication failure",
		"Unsupported protocol for file transfer",
		"Download failure: unable to join multicast group",
		"Download failure: unable to contact file server",
		"Download failure: unable to access file",
		"Download failure: unable to complete download",
		"Download failure: file corrupted",
		"Download failure: file authentication failure",
	};
	char buf[20];
	struct xml_kv fault[] = {
		{ "FaultCode", buf },
		{ "FaultString", "unspecified error" },
	};

	if (code > 9000 && code - 9000 < ARRAY_SIZE(fault_msg))
		fault[1].value = fault_msg[code - 9000];

	snprintf(buf, sizeof(buf), "%d", code);
	xml_add_multi(node, ROXML_ELM_NODE, ARRAY_SIZE(fault), fault, NULL);
}

static const char *soap_get_faultcode(int code)
{
	switch(code) {
	case 9003:
	case 9005:
	case 9006:
	case 9007:
	case 9008:
		return "Client";
	default:
		return "Server";
	}
}

node_t *soap_add_fault(node_t *node, int code)
{
	const char *faultcode = soap_get_faultcode(code);
	struct xml_kv fault[] = {
		{ "faultcode", faultcode },
		{ "faultstring", "CWMP fault" },
	};

	node = roxml_add_node(node, 0, ROXML_ELM_NODE, "soap:Fault", NULL);
	xml_add_multi(node, ROXML_ELM_NODE, ARRAY_SIZE(fault), fault, NULL);
	node = roxml_add_node(node, 0, ROXML_ELM_NODE, "detail", NULL);
	node = roxml_add_node(node, 0, ROXML_ELM_NODE, "cwmp:Fault", NULL);
	soap_add_fault_struct(node, code);

	return node;
}

static char *soap_msg_done(node_t *node, enum soap_response res)
{
	char *buf;

	if (!node)
		return NULL;

	node = roxml_get_root(node);

	switch (res) {
	case SOAP_RESPONSE_NONE:
		buf = NULL;
		break;
	case SOAP_RESPONSE_EMPTY:
		buf = "";
		break;
	case SOAP_RESPONSE_DATA:
		roxml_commit_changes(node, NULL, &buf, 0);
		break;
	}

	roxml_close(node);

	return buf;
}

char *__soap_get_field(node_t *node, const char *name, char *buf, int len)
{
	node = roxml_get_chld(node, (char *) name, 0);
	if (!node)
		return NULL;

	return roxml_get_content(node, buf, len, NULL);
}

int soap_get_boolean_field(node_t *node, const char *name, bool *val)
{
	char buf[8];

	if (!__soap_get_field(node, name, buf, sizeof(buf)))
		return -1;

	if (!strcmp(buf, "false") || !strcmp(buf, "0"))
		*val = false;
	else if (!strcmp(buf, "true") || !strcmp(buf, "1"))
		*val = true;
	else
		return -1;

	return 0;
}

int soap_get_int_field(node_t *node, const char *name, int *val)
{
	char buf[32];
	char *err;

	if (!__soap_get_field(node, name, buf, sizeof(buf)))
		return -1;

	*val = strtoul(buf, &err, 0);
	if (err && *err)
		return -1;

	return 0;
}

static bool soap_node_check_type(node_t *node, const char *type)
{
	int len = strlen(type) + 2;
	char *buf = alloca(len);

	if (!roxml_get_name(node, buf, len))
		return false;

	/* ignore type parameters */
	if (buf[len - 1] == '(')
		buf[len - 1] = 0;

	return !strcmp(buf, type);
}

node_t *soap_array_start(node_t *node, const char *name, int *len)
{
	node = roxml_get_chld(node, (char *) name, 0);
	if (!node)
		return NULL;

	if (len)
		*len = roxml_get_chld_nb(node);

	return roxml_get_chld(node, NULL, 0);
}

bool soap_array_iterate(node_t **cur, const char *type, node_t **node)
{
	if (!cur || !*cur)
		return false;

	if (!soap_node_check_type(*cur, type))
		return false;

	*node = *cur;
	*cur = roxml_get_next_sibling(*cur);

	return !!*node;
}

bool soap_array_iterate_contents(node_t **cur, const char *type, char **str)
{
	node_t *node;

	roxml_release(*str);
	*str = NULL;

	if (!soap_array_iterate(cur, type, &node))
		return false;

	*str = roxml_get_content(node, NULL, 0, NULL);
	return true;
}

char *soap_init_session(void)
{
	struct rpc_data data = {};
	bool send_msg = true;

	data.out = soap_msg_new(NULL, true);

	if (cwmp_session_init(&data))
		send_msg = false;

	return soap_msg_done(data.out, send_msg);
}

char *soap_handle_msg(char *message)
{
	node_t *root = NULL, *node, *hdr;
	bool hold_requests = false;
	int code;

	struct rpc_data data = {};

	if (!message) {
		data.out = soap_msg_new(NULL, false);
		data.empty_message = true;
		goto out;
	}

	root = roxml_load_buf(message);
	node = roxml_get_chld(root, "Envelope", 0);
	if (!node)
		goto parse_out;

	hdr = roxml_get_chld(node, "Header", 0);
	if (hdr) {
		data.id = soap_get_field(hdr, "ID");
		if (soap_get_boolean_field(hdr, "HoldRequests", &hold_requests))
			hold_requests = false;
	}

	node = roxml_get_chld(node, "Body", 0);
	if (!node)
		goto parse_out;

	data.in = roxml_get_chld(node, NULL, 0);
	if (!data.in)
		goto parse_out;

	data.method = roxml_get_name(data.in, NULL, 0);
	if (!data.method)
		goto parse_out;

	data.out = soap_msg_new(data.id, false);
	if (!data.out)
		goto out;

	code = cwmp_session_response(&data);
	if (code) {
		data.response = SOAP_RESPONSE_DATA;
		soap_add_fault(data.out, code);
	}

parse_out:
	roxml_release(data.id);
	roxml_release(data.method);
	roxml_close(root);

out:
	if (!data.response && data.out)
		cwmp_session_continue(&data);

	return soap_msg_done(data.out, data.response);
}
