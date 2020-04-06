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
#include <sys/stat.h>

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libubox/utils.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>

#include "state.h"
#include "strncpyt.h"

#ifdef DUMMY_MODE
#define CWMP_ETC_DIR "./etc"
#define CWMP_SESSION_BIN "./cwmp-session"
#define CWMP_SCRIPT_DIR "./scripts"
#else
#define CWMP_ETC_DIR "/etc"
#define CWMP_SESSION_BIN "cwmp-session"
#define CWMP_SCRIPT_DIR "/usr/share/cwmp/scripts"
#endif

#define CWMP_CACHE_FILE	CWMP_ETC_DIR "/cwmp-cache.json"
#define CWMP_STARTUP_FILE	CWMP_ETC_DIR "/cwmp-startup.json"

#define CWMP_SESSION_ERR_RETRY_MSEC	(10 * 1000)

static const char *session_path = CWMP_SESSION_BIN;
static const char *cache_file = CWMP_CACHE_FILE;
static struct blob_buf b;
static bool session_pending;

struct cwmp_config config;
enum pending_cmd pending_cmd = CMD_NONE;
bool session_success = false;
int debug_level;

static void __cwmp_session_timer(struct uloop_timeout *timeout);

static struct uloop_timeout session_timer = {
	.cb = __cwmp_session_timer,
};


static char *cwmp_get_event_str(bool pending)
{
	void *c;

	blob_buf_init(&b, 0);
	c = blobmsg_open_array(&b, NULL);
	cwmp_state_get_events(&b, pending);
	blobmsg_close_array(&b, c);
	return blobmsg_format_json(blob_data(b.head), false);
}

static void __cwmp_save_cache(struct uloop_timeout *timeout)
{
	char *str;
	FILE *f;
	void *c;

	if (!config.acs.url[0])
		return;

	blob_buf_init(&b, 0);

	f = fopen(cache_file, "w+");
	if (!f)
		return;

	blobmsg_add_string(&b, "acs_url", config.acs.url);

	c = blobmsg_open_array(&b, "events");
	cwmp_state_get_events(&b, false);
	blobmsg_close_array(&b, c);

	c = blobmsg_open_array(&b, "downloads");
	cwmp_state_get_downloads(&b);
	blobmsg_close_array(&b, c);

	str = blobmsg_format_json(b.head, true);
	if (debug_level)
		fprintf(stderr, "Updated cache: %s\n", str);
	fwrite(str, strlen(str), 1, f);
	free(str);

	fclose(f);
}

static struct uloop_timeout save_cache = {
	.cb = __cwmp_save_cache,
};

static void session_cb(struct uloop_process *c, int ret);
static struct uloop_process session_proc = {
	.cb = session_cb
};

static void cwmp_exec_session(const char *event_data)
{
	static char debug_str[8] = "0";
	const char *argv[12] = {
		session_path,
		"-d",
		debug_str,
		"-e",
		event_data,
		NULL
	};
	int argc = 5;

	if (config.acs.usr[0]) {
		argv[argc++] = "-u";
		argv[argc++] = config.acs.usr;
	}
	if (config.acs.pwd[0]) {
		argv[argc++] = "-p";
		argv[argc++] = config.acs.pwd;
	}

	argv[argc++] = config.acs.url;
	argv[argc] = NULL;
	snprintf(debug_str, sizeof(debug_str), "%d", debug_level);

	if (execvp(argv[0], (char * const *) argv) == -1)
		fprintf(stderr, "execvp of %s failed: %s\n", argv[0], strerror(errno));
	exit(255);
}

void cwmp_download_apply_exec(const char *path, const char *type, const char *file, const char *url)
{
	const char *argv[] = {
		CWMP_SCRIPT_DIR "/apply.sh",
		path,
		type,
		file,
		url,
		NULL,
	};

	execvp(argv[0], (char **) argv);
	exit(255);
}

static void cwmp_run_session(void)
{
	char *ev;
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

	ev = cwmp_get_event_str(true);
	cwmp_exec_session(ev);
	free(ev);
}

static void cwmp_process_pending_cmd(void)
{
	const char *cmd;

	switch (pending_cmd) {
	case CMD_FACTORY_RESET:
		cmd = CWMP_SCRIPT_DIR "/factory-reset.sh";
		break;
	case CMD_REBOOT:
		cmd = CWMP_SCRIPT_DIR "/reboot.sh";
		break;
	default:
		return;
	}

	system(cmd);
}

static void session_cb(struct uloop_process *c, int ret)
{
	cwmp_process_pending_cmd();
	cwmp_download_check_pending(true);

	if (debug_level)
		fprintf(stderr, "Session completed (rc: %d success: %d)\n",
			ret, session_success);

	if (ret)
		cwmp_schedule_session(CWMP_SESSION_ERR_RETRY_MSEC);
	else if (session_pending)
		cwmp_schedule_session(1);
}

static void __cwmp_run_session(struct uloop_timeout *timeout)
{
	if (session_proc.pending) {
		session_pending = true;
		return;
	}

	if (!cwmp_state_has_events())
		return;

	if (!config.acs.url[0])
		return;

	cwmp_run_session();
}

void cwmp_schedule_session(int delay_msec)
{
	static struct uloop_timeout timer = {
		.cb = __cwmp_run_session,
	};

	uloop_timeout_set(&timer, delay_msec);
}

static void cwmp_update_session_timer(void)
{
	if (config.acs.periodic_interval && config.acs.periodic_enabled)
		uloop_timeout_set(&session_timer,
				config.acs.periodic_interval * 1000);
	else
		uloop_timeout_cancel(&session_timer);
}

static void __cwmp_session_timer(struct uloop_timeout *timeout)
{
	cwmp_schedule_session(1);
	cwmp_flag_event("2 PERIODIC", NULL, NULL);
	cwmp_update_session_timer();
}

void cwmp_save_cache(bool immediate)
{
	if (immediate) {
		uloop_timeout_cancel(&save_cache);
		save_cache.cb(&save_cache);
	} else {
		uloop_timeout_set(&save_cache, 1);
	}
}

static void cwmp_add_downloads(struct blob_attr *attr)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, attr, rem)
		cwmp_download_add(cur, true);
}

static void cwmp_load_cache(const char *filename)
{
	enum {
		CACHE_URL,
		CACHE_EVENTS,
		CACHE_DOWNLOADS,
		__CACHE_MAX,
	};
	static const struct blobmsg_policy policy[__CACHE_MAX] = {
		[CACHE_URL] = { "acs_url", BLOBMSG_TYPE_STRING },
		[CACHE_EVENTS] = { "events", BLOBMSG_TYPE_ARRAY },
		[CACHE_DOWNLOADS] = { "downloads", BLOBMSG_TYPE_ARRAY }
	};
	struct blob_attr *tb[__CACHE_MAX], *cur;
	struct stat st;

	if (stat(filename, &st) != 0)
		goto bootstrap;

	blob_buf_init(&b, 0);
	if (!blobmsg_add_json_from_file(&b, filename))
		goto bootstrap;

	blobmsg_parse(policy, __CACHE_MAX, tb, blob_data(b.head), blob_len(b.head));

	if ((cur = tb[CACHE_EVENTS]))
		cwmp_add_events(cur);

	if ((cur = tb[CACHE_DOWNLOADS]))
		cwmp_add_downloads(cur);

	if (config.acs.url[0]) {
		cur = tb[CACHE_URL];
		if (!cur || strcmp(config.acs.url, blobmsg_data(cur)) != 0)
			goto bootstrap;
	}
	return;

bootstrap:
	cwmp_flag_event("0 BOOTSTRAP", NULL, NULL);
}

static void cwmp_load_startup(const char *filename)
{
	static const struct blobmsg_policy policy = {
		"commands", BLOBMSG_TYPE_ARRAY
	};
	struct blob_attr *attr, *cur;
	struct stat st;
	int rem;

	if (stat(filename, &st) != 0)
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_json_from_file(&b, filename);
	truncate(filename, 0);

	blobmsg_parse(&policy, 1, &attr, blob_data(b.head), blob_len(b.head));
	if (!attr)
		return;

	if (!blobmsg_check_attr_list(attr, BLOBMSG_TYPE_ARRAY))
		return;

	blobmsg_for_each_attr(cur, attr, rem)
		cwmp_ubus_command(cur);
}

static const char usage[] =
"Usage: %s <options>\n"
"options:\n"
" Daemon:\n"
"	--cache-file, -c <file>     CWMP cache storage file (default: " CWMP_CACHE_FILE ")\n"
"	--debug, -d                 Increase debug level\n"
"	--session-path, -s <path>   Path to session tool\n"
" ACS:\n"
"	--acs-url, -a <url>             URL of the ACS\n"
"	--acs-user, -u <username>       ACS login username\n"
"	--acs-pass, -p <password>       ACS login password\n"
"	--periodic-enable, -e           Enable ACS periodic informs\n"
"	--periodic-interval, -i <sec>   Set ACS periodic inform interval in seconds\n"
" CPE:\n"
"       --cpe-user, -U <username>   CPE login username\n"
"       --cpe-pass, -P <password>   CPE login password\n"
"";

static struct option long_options[] = {
	{ "cache-file", required_argument, 0, 'c' },
	{ "debug", no_argument, 0, 'd' },
	{ "session-path", required_argument, 0, 's' },
	/* acs */
	{ "acs-url", required_argument, 0, 'a' },
	{ "acs-user", required_argument, 0, 'u' },
	{ "acs-pass", required_argument, 0, 'p' },
	{ "periodic-enable", no_argument, 0, 'e' },
	{ "periodic-interval", required_argument, 0, 'i' },
	/* cpe */
	{ "cpe-user", required_argument, 0, 'U' },
	{ "cpe-pass", required_argument, 0, 'P' },
	{ 0, 0, 0, 0 }
};

static int parse_args(int argc, char **argv)
{
	int option_index = 0;
	int c;

	while ((c = getopt_long(argc, argv, "c:ds:a:u:p:U:P:ei:",
				 long_options, &option_index)) != -1) {
		switch(c) {
		case 'c':
			cache_file = optarg;
			break;
		case 'd':
			debug_level++;
			break;
		case 's':
			session_path = optarg;
			break;
		case 'a':
			strncpyt(config.acs.url, optarg,
				sizeof(config.acs.url));
			break;
		case 'u':
			strncpyt(config.acs.usr, optarg,
				sizeof(config.acs.usr));
			break;
		case 'p':
			strncpyt(config.acs.pwd, optarg,
				sizeof(config.acs.pwd));
			break;
		case 'e':
			config.acs.periodic_enabled = true;
			break;
		case 'i':
			config.acs.periodic_interval = atoi(optarg);
			break;
		case 'U':
			strncpyt(config.cpe.usr, optarg,
				sizeof(config.cpe.usr));
			break;
		case 'P':
			strncpyt(config.cpe.pwd, optarg,
				sizeof(config.cpe.pwd));
			break;
		default:
			return -1;
		}
	}
	return 0;
}

void cwmp_reload(bool acs_changed)
{
	if (acs_changed)
		__cwmp_session_timer(&session_timer);
}

int main(int argc, char **argv)
{
	int rc;

	rc = parse_args(argc, argv);
	if (rc < 0) {
		puts(usage);
		return 1;
	}

	uloop_init();

	if (cwmp_ubus_register()) {
		fprintf(stderr, "Failed to register ubus object\n");
		return 1;
	}

	cwmp_load_cache(cache_file);
	cwmp_download_check_pending(true);
	cwmp_load_startup(CWMP_STARTUP_FILE);

	uloop_timeout_cancel(&save_cache);
	cwmp_schedule_session(1);
	cwmp_update_session_timer();
	uloop_run();
	uloop_done();

	return 0;
}
