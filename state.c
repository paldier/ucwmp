#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "state.h"

struct event_multi {
	struct event_multi *next;
	enum cwmp_event_multi idx;
	char data[];
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

static struct blob_buf b;

static void event_add(const char *id, const char *key)
{
	void *e = blobmsg_open_array(&b, NULL);

	blobmsg_add_string(&b, NULL, id);
	if (key && *key)
		blobmsg_add_string(&b, NULL, key);
	blobmsg_close_array(&b, e);
}

char *cwmp_state_get_events(void)
{
	struct event_multi **tail = &event_multi_pending;
	struct event_multi *cur = *tail;
	void *c;
	int i;

	event_pending |= event_flagged;
	event_flagged = 0;

	if (event_pending & (1 << EVENT_BOOTSTRAP))
		event_pending = 1 << EVENT_BOOTSTRAP;

	blob_buf_init(&b, 0);

	c = blobmsg_open_array(&b, NULL);

	for (i = 0; i < __EVENT_MAX; i++) {
		if (!(event_pending & (1 << i)))
			continue;

		event_add(event_codes[i], event_command_key[i]);
	}

	for (tail = &event_multi_pending; *tail; cur = *tail, tail = &cur->next)
		event_add(event_multi_codes[cur->idx], cur->data);

	*tail = event_multi_flagged;
	event_multi_flagged = NULL;

	for (cur = *tail; cur; cur = cur->next)
		event_add(event_multi_codes[cur->idx], cur->data);

	blobmsg_close_array(&b, c);

	return blobmsg_format_json(blob_data(b.head), false);
}

void cwmp_flag_event(const char *id, const char *command_key)
{
	struct event_multi *ev;
	int i;

	for (i = 0; i < __EVENT_MAX; i++) {
		if (strcmp(id, event_codes[i]) != 0)
			continue;

		event_flagged |= (1 << i);
		free(event_command_key[i]);
		event_command_key[i] = command_key ? strdup(command_key) : "";
		return;
	}

	for (i = 0; i < __EVENT_M_MAX; i++) {
		if (strcmp(id, event_multi_codes[i]) != 0)
			continue;

		if (!command_key)
			command_key = "";

		ev = calloc(1, sizeof(*ev) + strlen(id) + 1);
		ev->idx = i;
		strcpy(ev->data, command_key);

		ev->next = event_multi_flagged;
		event_multi_flagged = ev;
		return;
	}
}
