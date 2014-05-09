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
#ifndef __UCWMP_CWMP_H
#define __UCWMP_CWMP_H

#include <netinet/in.h>
#include <libubox/avl.h>
#include <libubox/blobmsg.h>
#include <roxml.h>

#include "soap.h"

#define CWMP_PATH_LEN	256

enum cwmp_error {
	CWMP_ERROR_INVALID_METHOD =		9000,
	CWMP_ERROR_REQUEST_DENIED =		9001,
	CWMP_ERROR_INTERNAL_ERROR =		9002,
	CWMP_ERROR_INVALID_ARGUMENTS =		9003,
	CWMP_ERROR_RESOURCES_EXCEEDED =		9004,
	CWMP_ERROR_INVALID_PARAM =		9005,
	CWMP_ERROR_INVALID_PARAM_TYPE =		9006,
	CMWP_ERROR_INVALID_PARAM_VAL =		9007,
	CWMP_ERROR_READ_ONLY_PARAM =		9008,
	CWMP_ERROR_NOTIFICATION_REJECTED =	9009,
	CWMP_ERROR_FILE_DOWNLOAD_FAILED =	9010,
	CWMP_ERROR_FILE_UPLOAD_FAILED =		9011,
	CWMP_ERROR_FILE_XFER_AUTH_FAILED =	9012,
	CWMP_ERROR_FILE_INVALID_PROTO =		9013,
	CWMP_ERROR_FILE_MULTICAST_FAILED =	9014,
	CWMP_ERROR_FILE_CONNECTION_FAILED =	9015,
	CWMP_ERROR_FILE_ACCESS_FAILED =		9016,
	CWMP_ERROR_FILE_COMPLETION_FAILED =	9017,
	CWMP_ERROR_FILE_CORRUPTED =		9018,
	CWMP_ERROR_FILE_AUTH_FAILED =		9019,
};

struct rpc_data {
	char *id;
	char *method;

	node_t *in;
	node_t *out;

	enum soap_response response;
	bool empty_message;

	/* for specific RPC calls */
	int n_values;
	node_t *values;
};

struct rpc_method {
	const char *name;
	int (*handler) (struct rpc_data *data);
};

extern bool session_init;
extern struct blob_buf events;

int cwmp_session_init(struct rpc_data *data);
int cwmp_session_response(struct rpc_data *data);
void cwmp_session_continue(struct rpc_data *data);

void cwmp_add_device_id(node_t *node);
void server_load_info(const char *filename);
void server_update_local_addr(const char *addr);
void cwmp_update_url(const char *url, const char *auth_str);
void cwmp_load_events(const char *filename);
void cwmp_clear_pending_events(void);

void cwmp_add_parameter_value_struct(node_t *node, const char *name, const char *value, const char *type);

int cwmp_invoke(const char *cmd, struct blob_attr *data);
int cwmp_invoke_noarg(const char *cmd);


#endif
