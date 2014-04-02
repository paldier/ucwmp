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

enum {
	SERVER_INFO_URL,
	SERVER_INFO_USERNAME,
	SERVER_INFO_PASSWORD,
	SERVER_INFO_PERIODIC_INTERVAL,
	SERVER_INFO_PERIODIC_ENABLED,
	__SERVER_INFO_MAX
};

enum cwmp_config_change {
	CONFIG_CHANGE_ACS_INFO,
	CONFIG_CHANGE_PERIODIC_INFO,
};

struct cwmp_config {
	const char *acs_info[3];

	int periodic_interval;
	bool periodic_enabled;
};

extern struct cwmp_config config;

char *cwmp_state_get_events(bool move_pending);
void cwmp_flag_event(const char *id, const char *command_key);
void cwmp_load_events(const char *filename);
void cwmp_events_changed(bool add);
void cwmp_clear_pending_events(void);

int cwmp_update_config(enum cwmp_config_change changed);

int cwmp_ubus_register(void);

#endif
