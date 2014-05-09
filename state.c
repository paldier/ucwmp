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
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "state.h"

struct event_multi {
	struct event_multi *next;
	enum cwmp_event_multi idx;
	struct blob_attr *data;
	char command_key[];
};

static const char *event_codes[__EVENT_MAX] = {
	[EVENT_BOOTSTRAP] = "0 BOOTSTRAP",
	[EVENT_BOOT] = "1 BOOT",
	[EVENT_PERIODIC] = "2 PERIODIC",
	[EVENT_SCHEDULED] = "3 SCHEDULED",
	[EVENT_REQUEST] = "6 CONNECTION REQUEST",
	[EVENT_TRANSFER_COMPLETE] = "7 TRANSFER COMPLETE",
};

static const char *event_multi_codes[__EVENT_M_MAX] = {
	[EVENT_M_REBOOT] = "M Reboot",
	[EVENT_M_SCHEDULE_INFORM] = "M ScheduleInform",
	[EVENT_M_DOWNLOAD] = "M Download",
	[EVENT_M_SCHEDULE_DOWNLOAD] = "M ScheduleDownload",
	[EVENT_M_UPLOAD] = "M Upload",
};

static unsigned long event_pending;
static unsigned long event_flagged;
static char *event_command_key[__EVENT_MAX];

static struct event_multi *event_multi_pending;
static struct event_multi *event_multi_flagged;

static void event_add(struct blob_buf *buf, const char *id, const char *key, struct blob_attr *data)
{
	void *e = blobmsg_open_array(buf, NULL);

	blobmsg_add_string(buf, NULL, id);
	if (key && *key)
		blobmsg_add_string(buf, NULL, key);
	if (data)
		blobmsg_add_field(buf, BLOBMSG_TYPE_TABLE, "data",
				  blobmsg_data(data), blobmsg_data_len(data));
	blobmsg_close_array(buf, e);
}

static void event_free_multi(struct event_multi **head)
{
	struct event_multi *cur;

	while (*head) {
		cur = *head;
		*head = cur->next;
		free(cur);
	}
}

void cwmp_clear_pending_events(void)
{
	event_pending = 0;
	event_free_multi(&event_multi_pending);
	cwmp_save_cache(false);
}

bool cwmp_state_has_events(void)
{
	return (event_pending || event_flagged ||
		event_multi_pending || event_multi_flagged);
}

void cwmp_state_get_events(struct blob_buf *buf, bool pending)
{
	struct event_multi **tail = &event_multi_pending;
	struct event_multi *cur = *tail;
	unsigned int cur_pending;
	int i;

	cur_pending = event_pending | event_flagged;

	if (pending) {
		event_pending = cur_pending;
		event_flagged = 0;
	}

	if (cur_pending & (1 << EVENT_BOOTSTRAP)) {
		cur_pending = 1 << EVENT_BOOTSTRAP;
		event_free_multi(&event_multi_pending);
		event_free_multi(&event_multi_flagged);
	}

	for (i = 0; i < __EVENT_MAX; i++) {
		if (!(cur_pending & (1 << i)))
			continue;

		event_add(buf, event_codes[i], event_command_key[i], NULL);
	}

	for (tail = &event_multi_pending; *tail; cur = *tail, tail = &cur->next)
		event_add(buf, event_multi_codes[cur->idx], cur->command_key, cur->data);

	if (pending) {
		*tail = event_multi_flagged;
		event_multi_flagged = NULL;
	} else {
		tail = &event_multi_flagged;
	}

	for (cur = *tail; cur; cur = cur->next)
		event_add(buf, event_multi_codes[cur->idx], cur->command_key, cur->data);
}

void cwmp_flag_event(const char *id, const char *command_key, struct blob_attr *data)
{
	struct event_multi *ev;
	int i;

	for (i = 0; i < __EVENT_MAX; i++) {
		if (strcmp(id, event_codes[i]) != 0)
			continue;

		event_flagged |= (1 << i);
		free(event_command_key[i]);
		event_command_key[i] = command_key ? strdup(command_key) : NULL;
		goto out;
	}

	for (i = 0; i < __EVENT_M_MAX; i++) {
		struct blob_attr *extra;

		if (strcmp(id, event_multi_codes[i]) != 0)
			continue;

		if (!command_key)
			command_key = "";

		switch (i) {
		case EVENT_M_UPLOAD:
		case EVENT_M_DOWNLOAD:
		case EVENT_M_SCHEDULE_DOWNLOAD:
			event_flagged |= (1 << EVENT_TRANSFER_COMPLETE);
			break;
		}

		ev = calloc_a(sizeof(*ev) + strlen(id) + 1,
			&extra, data ? blob_pad_len(data) : 0);
		ev->idx = i;
		if (data)
			ev->data = memcpy(extra, data, blob_pad_len(data));
		strcpy(ev->command_key, command_key);

		ev->next = event_multi_flagged;
		event_multi_flagged = ev;
		goto out;
	}

	return;

out:
	cwmp_schedule_session();
	cwmp_save_cache(false);
}

void cwmp_add_events(struct blob_attr *attr)
{
	static const struct blobmsg_policy ev_attr[3] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, attr, rem) {
		struct blob_attr *tb[3];

		blobmsg_parse_array(ev_attr, ARRAY_SIZE(ev_attr), tb,
				    blobmsg_data(cur), blobmsg_data_len(cur));

		if (!tb[0])
			continue;

		cwmp_flag_event(blobmsg_data(tb[0]),
				tb[1] ? blobmsg_data(tb[1]) : NULL,
				tb[2]);
	}

}

