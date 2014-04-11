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
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <uci.h>

#include <libubox/utils.h>
#include <libubox/uloop.h>

#include "state.h"

#ifdef DUMMY_MODE
#define CWMP_CONFIG_DIR	"./examples/config"
#define CWMP_INFO_DIR "./examples"
#define CWMP_SESSION_BIN "./cwmp-session"
#else
#define CWMP_CONFIG_DIR	NULL /* UCI default */
#define CWMP_INFO_DIR "/etc/cwmp"
#define CWMP_SESSION_BIN "cwmp-session"
#endif

#define CWMP_INFO_FILE	CWMP_INFO_DIR "/cwmp-device.json"
#define CWMP_EVENT_FILE	CWMP_INFO_DIR "/events.json"

static struct uci_context *uci_ctx;
static const char *session_path = CWMP_SESSION_BIN;
static const char *devinfo_path = CWMP_INFO_FILE;
static const char *config_path = CWMP_CONFIG_DIR;
static const char *events_file = CWMP_EVENT_FILE;

bool session_success = false;
static bool session_pending;
static int debug_level;

struct cwmp_config config;

static const struct uci_parse_option server_opts[__SERVER_INFO_MAX] = {
	[SERVER_INFO_URL] = { "url", UCI_TYPE_STRING },
	[SERVER_INFO_USERNAME] = { "username", UCI_TYPE_STRING },
	[SERVER_INFO_PASSWORD] = { "password", UCI_TYPE_STRING },

	[SERVER_INFO_PERIODIC_INTERVAL] = { "periodic_interval", UCI_TYPE_STRING },
	[SERVER_INFO_PERIODIC_ENABLED] = { "periodic_enabled", UCI_TYPE_STRING },
	[SERVER_INFO_CONN_REQ_PORT] = { "connection_port", UCI_TYPE_STRING },

	[SERVER_INFO_LOCAL_USERNAME] = { "local_username", UCI_TYPE_STRING },
	[SERVER_INFO_LOCAL_PASSWORD] = { "local_password", UCI_TYPE_STRING },
};

static void __cwmp_save_events(struct uloop_timeout *timeout)
{
	char *events = cwmp_state_get_events(false);
	FILE *f;

	f = fopen(events_file, "w+");
	if (!f)
		return;

	fwrite(events, strlen(events), 1, f);
	fclose(f);

	free(events);
}

static struct uloop_timeout save_events = {
	.cb = __cwmp_save_events,
};

static void session_cb(struct uloop_process *c, int ret);
static struct uloop_process session_proc = {
	.cb = session_cb
};

static void cwmp_exec_session(const char *event_data)
{
	static char debug_str[8] = "0";
	const char *argv[16] = {
		session_path,
		"-d",
		debug_str,
		"-e",
		event_data,
		"-I",
		devinfo_path,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	};
	int argc = 7;

	if (config.acs_info[1]) {
		argv[argc++] = "-u";
		argv[argc++] = config.acs_info[1];
	}
	if (config.acs_info[2]) {
		argv[argc++] = "-p";
		argv[argc++] = config.acs_info[2];
	}

	argv[argc++] = config.acs_info[0];
	snprintf(debug_str, sizeof(debug_str), "%d", debug_level);
	execvp(argv[0], (char * const *) argv);
	exit(255);
}

static void cwmp_run_session(void)
{
	char *ev = cwmp_state_get_events(true);
	int pid;

	session_pending = false;
	session_success = false;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return;
	}

	if (pid > 0) {
		session_proc.pid = pid;
		uloop_process_add(&session_proc);
		return;
	}

	cwmp_exec_session(ev);
	free(ev);
}

static void session_cb(struct uloop_process *c, int ret)
{
	if (debug_level)
		fprintf(stderr, "Session completed (success: %d)\n", session_success);

	if (session_pending)
		cwmp_run_session();
}

static void cwmp_schedule_session(void)
{
	if (session_proc.pending) {
		session_pending = true;
		return;
	}
	cwmp_run_session();
}

static void cwmp_update_session_timer(void);
static void __cwmp_session_timer(struct uloop_timeout *timeout)
{
	cwmp_schedule_session();
	cwmp_flag_event("2 PERIODIC", NULL);
	cwmp_update_session_timer();
}

static void cwmp_update_session_timer(void)
{
	static struct uloop_timeout timer = {
		.cb = __cwmp_session_timer,
	};

	if (config.periodic_interval && config.periodic_enabled)
		uloop_timeout_set(&timer, config.periodic_interval * 1000);
	else
		uloop_timeout_cancel(&timer);
}

void cwmp_events_changed(bool add)
{
	if (add)
		cwmp_schedule_session();
	uloop_timeout_set(&save_events, 1);
}

static int cwmp_get_config_section(struct uci_ptr *ptr)
{
	static char buf[32];

	strcpy(buf, "cwmp.@cwmp[0]");
	if (uci_lookup_ptr(uci_ctx, ptr, buf, true)) {
		uci_perror(uci_ctx, "Failed to load configuration");
		return -1;
	}

	return 0;
}

static int cwmp_load_config(void)
{
	struct uci_option *tb[__SERVER_INFO_MAX], *cur;
	struct uci_ptr ptr = {};
	int i;

	memset(&config, 0, sizeof(config));
	config.conn_req_port = DEFAULT_CONNECTION_PORT;

	if (cwmp_get_config_section(&ptr))
		return -1;

	uci_parse_section(ptr.s, server_opts, ARRAY_SIZE(server_opts), tb);
	if (!tb[SERVER_INFO_URL]) {
		fprintf(stderr, "ACS URL not found in config\n");
		return -1;
	}

	for (i = 0; i <= SERVER_INFO_PASSWORD; i++) {
		const char *val = tb[i] ? tb[i]->v.string : NULL;

		config.acs_info[i - SERVER_INFO_URL] = val;
	}

	if ((cur = tb[SERVER_INFO_PERIODIC_INTERVAL]))
		config.periodic_interval = atoi(cur->v.string);

	if ((cur = tb[SERVER_INFO_PERIODIC_ENABLED]))
		config.periodic_enabled = atoi(cur->v.string);

	if ((cur = tb[SERVER_INFO_CONN_REQ_PORT]))
		config.conn_req_port = atoi(cur->v.string);

	if ((cur = tb[SERVER_INFO_LOCAL_USERNAME]))
		config.local_username = cur->v.string;

	if ((cur = tb[SERVER_INFO_LOCAL_PASSWORD]))
		config.local_password = cur->v.string;

	return 0;
}

static void cwmp_set_string_option(struct uci_ptr *ptr, const char *name, const char *val)
{
	ptr->o = NULL;
	ptr->option = name;
	uci_lookup_ptr(uci_ctx, ptr, NULL, false);

	ptr->value = val;
	if (ptr->value)
		uci_set(uci_ctx, ptr);
	else if (ptr->o)
		uci_delete(uci_ctx, ptr);
}

static void cwmp_set_int_option(struct uci_ptr *ptr, const char *name, int val)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%d", val);
	cwmp_set_string_option(ptr, name, buf);
}

int cwmp_update_config(enum cwmp_config_change changed)
{
	struct uci_ptr ptr = {};
	int i;

	if (cwmp_get_config_section(&ptr))
		return -1;

	switch (changed) {
	case CONFIG_CHANGE_ACS_INFO:
		for (i = 0; i < ARRAY_SIZE(config.acs_info); i++)
			cwmp_set_string_option(&ptr, server_opts[i].name, config.acs_info[i]);

		cwmp_flag_event("0 BOOTSTRAP", NULL);
		break;
	case CONFIG_CHANGE_PERIODIC_INFO:
		cwmp_set_int_option(&ptr, "periodic_interval", config.periodic_interval);
		cwmp_set_int_option(&ptr, "periodic_enabled", config.periodic_enabled);
		cwmp_update_session_timer();
		break;

	case CONFIG_CHANGE_LOCAL_INFO:
		cwmp_set_string_option(&ptr, "local_username", config.local_username);
		cwmp_set_string_option(&ptr, "local_password", config.local_password);
		break;
	}

	return 0;
}

void cwmp_commit_config(void)
{
	struct uci_ptr ptr = {};

	if (cwmp_get_config_section(&ptr))
		return;

	uci_commit(uci_ctx, &ptr.p, false);
	cwmp_load_config();
}

static int usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <options>\n"
		"Options:\n"
		"	-c <path>       Path to UCI config file (default: %s)\n"
		"	-I <file>       Device information file (default: " CWMP_INFO_FILE ")\n"
		"	-E <file>       CWMP events storage file (default: " CWMP_EVENT_FILE ")\n"
		"	-d              Increase debug level\n"
		"	-s <path>       Path to session tool\n"
		"\n", prog, CWMP_CONFIG_DIR ? CWMP_CONFIG_DIR : UCI_CONFDIR);
	return 1;
}

int main(int argc, char **argv)
{
	int ch;

	uci_ctx = uci_alloc_context();

	while ((ch = getopt(argc, argv, "c:dE:I:s:")) != -1) {
		switch(ch) {
		case 'c':
			config_path = optarg;
			break;
		case 'I':
			devinfo_path = optarg;
			break;
		case 'E':
			events_file = optarg;
			break;
		case 'd':
			debug_level++;
			break;
		case 's':
			session_path = optarg;
			break;
		default:
			return usage(argv[0]);
		}
	}

	uci_set_confdir(uci_ctx, config_path);

	if (cwmp_load_config() < 0)
		return 1;

	uloop_init();

	if (cwmp_ubus_register()) {
		fprintf(stderr, "Failed to register ubus object\n");
		return 1;
	}

	cwmp_load_events(events_file);
	uloop_timeout_cancel(&save_events);
	cwmp_schedule_session();
	cwmp_update_session_timer();
	uloop_run();
	uloop_done();

	return 0;
}
