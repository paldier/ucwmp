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
#ifndef __UCWMP_STATE_H
#define __UCWMP_STATE_H

#include <libubox/blobmsg.h>

#define DEFAULT_CONNECTION_PORT	8080

enum cwmp_event_single {
	EVENT_BOOTSTRAP,
	EVENT_BOOT,
	EVENT_PERIODIC,
	EVENT_SCHEDULED,
	/* 4 VALUE CHANGE is checked and sent by the session process */
	EVENT_REQUEST,
	EVENT_TRANSFER_COMPLETE,
	__EVENT_MAX
};

enum cwmp_event_multi {
	EVENT_M_REBOOT,
	EVENT_M_SCHEDULE_INFORM,
	EVENT_M_DOWNLOAD,
	EVENT_M_SCHEDULE_DOWNLOAD,
	EVENT_M_UPLOAD,
	__EVENT_M_MAX
};

enum {
	SERVER_INFO_URL,
	SERVER_INFO_USERNAME,
	SERVER_INFO_PASSWORD,
	SERVER_INFO_PERIODIC_INTERVAL,
	SERVER_INFO_PERIODIC_ENABLED,
	SERVER_INFO_CONN_REQ_PORT,
	SERVER_INFO_LOCAL_USERNAME,
	SERVER_INFO_LOCAL_PASSWORD,
	__SERVER_INFO_MAX
};

enum cwmp_config_change {
	CONFIG_CHANGE_ACS_INFO,
	CONFIG_CHANGE_PERIODIC_INFO,
	CONFIG_CHANGE_LOCAL_INFO,
};

struct cwmp_config {
	const char *acs_info[3];

	int conn_req_port;
	int periodic_interval;
	bool periodic_enabled;

	const char *local_username;
	const char *local_password;
};

extern struct cwmp_config config;
extern bool session_success;

void cwmp_state_get_events(struct blob_buf *buf, bool pending);
void cwmp_flag_event(const char *id, const char *command_key);
void cwmp_load_events(const char *filename);
void cwmp_events_changed(bool add);
void cwmp_clear_pending_events(void);

int cwmp_update_config(enum cwmp_config_change changed);
void cwmp_commit_config(void);

int cwmp_ubus_register(void);

#endif
