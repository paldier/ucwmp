#ifndef __UCWMP_STATE_H
#define __UCWMP_STATE_H

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

char *cwmp_state_get_events(void);
void cwmp_flag_event(const char *id, const char *command_key);
void cwmp_load_events(const char *filename);
void cwmp_save_events(void);
void cwmp_clear_pending_events(void);

int cwmp_ubus_register(void);

#endif
