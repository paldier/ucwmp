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

#include <libubox/list.h>
#include <libubox/blobmsg.h>

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

struct acs_config {
	char url[128];
	char usr[64];
	char pwd[64];
	int periodic_interval;
	bool periodic_enabled;
};

struct cpe_config {
	char usr[64];
	char pwd[64];
};

struct cwmp_config {
	struct acs_config acs;
	struct cpe_config cpe;
};

enum pending_cmd {
	CMD_NONE,
	CMD_FACTORY_RESET,
	CMD_REBOOT,
};

extern enum pending_cmd pending_cmd;

enum cwmp_dl {
	CWMP_DL_CKEY,
	CWMP_DL_TYPE,
	CWMP_DL_URL,
	CWMP_DL_USERNAME,
	CWMP_DL_PASSWORD,
	CWMP_DL_STATE,
	CWMP_DL_START,
	CWMP_DL_FILENAME,
	__CWMP_DL_MAX,
};

extern struct cwmp_config config;
extern bool session_success;
extern const struct blobmsg_policy transfer_policy[__CWMP_DL_MAX];

void cwmp_add_events(struct blob_attr *attr);
void cwmp_state_get_events(struct blob_buf *buf, bool pending);
void cwmp_state_get_downloads(struct blob_buf *buf);
void cwmp_flag_event(const char *id, const char *command_key, struct blob_attr *data);
bool cwmp_state_has_events(void);
void cwmp_clear_pending_events(void);

void cwmp_schedule_session(int delay_msec);
void cwmp_save_cache(bool immediate);
void cwmp_reload(bool acs_changed);

void cwmp_download_add(struct blob_attr *data, bool internal);
void cwmp_download_check_pending(bool session_complete);
void cwmp_download_apply_exec(const char *path, const char *type, const char *file, const char *url);
void cwmp_download_done(struct blob_attr *attr);

int cwmp_ubus_register(void);
void cwmp_ubus_command(struct blob_attr *data);

void cwmp_object_cache_load(struct blob_attr *data);
void cwmp_object_cache_dump(struct blob_buf *buf);
struct blob_attr *cwmp_object_cache_get(const char *path, struct blob_attr *list);

#endif
