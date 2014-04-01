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
#define CWMP_SESSION_BIN "./session"
#else
#define CWMP_CONFIG_DIR	NULL /* UCI default */
#define CWMP_INFO_DIR "/etc/cwmp"
#define CWMP_SESSION_BIN "session"
#endif

#define CWMP_INFO_FILE	CWMP_INFO_DIR "/cwmp-device.json"
#define CWMP_EVENT_FILE	CWMP_INFO_DIR "/events.json"

static struct uci_context *uci_ctx;
static const char *session_path = CWMP_SESSION_BIN;
static const char *devinfo_path = CWMP_INFO_FILE;
static const char *config_path = CWMP_CONFIG_DIR;
static const char *events_file = CWMP_EVENT_FILE;

static char *acs_info[3];

static bool session_pending;
static int debug_level;

static const struct uci_parse_option acs_opts[] = {
	{ "url", UCI_TYPE_STRING },
	{ "username", UCI_TYPE_STRING },
	{ "password", UCI_TYPE_STRING },
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

	if (acs_info[1]) {
		argv[argc++] = "-u";
		argv[argc++] = acs_info[1];
	}
	if (acs_info[2]) {
		argv[argc++] = "-p";
		argv[argc++] = acs_info[2];
	}

	argv[argc++] = acs_info[0];
	snprintf(debug_str, sizeof(debug_str), "%d", debug_level);
	execvp(argv[0], (char * const *) argv);
	exit(255);
}

static void cwmp_run_session(void)
{
	char *ev = cwmp_state_get_events(true);
	int pid;

	session_pending = false;

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
	if (session_pending) {
		cwmp_run_session();
		return;
	}
}

static void cwmp_schedule_session(void)
{
	if (session_proc.pending) {
		session_pending = true;
		return;
	}
	cwmp_run_session();
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
	struct uci_option *tb[3];
	struct uci_ptr ptr = {};
	int i;

	if (cwmp_get_config_section(&ptr))
		return -1;

	uci_parse_section(ptr.s, acs_opts, ARRAY_SIZE(acs_opts), tb);
	if (!tb[0]) {
		fprintf(stderr, "ACS URL not found in config\n");
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(acs_info); i++) {
		const char *val = tb[i] ? tb[i]->v.string : NULL;

		free(acs_info[i]);
		acs_info[i] = val ? strdup(val) : NULL;
	}

	return 0;
}

int cwmp_set_acs_config(char *info[3])
{
	struct uci_ptr ptr = {};
	int i;

	if (cwmp_get_config_section(&ptr))
		return -1;

	for (i = 0; i < ARRAY_SIZE(acs_info); i++) {
		ptr.o = NULL;

		ptr.option = info[i];

		uci_lookup_ptr(uci_ctx, &ptr, NULL, false);
		if (!ptr.value && !info[i])
			continue;

		if (ptr.value && info[i] &&
		    !strcmp(ptr.value, info[i]))
			continue;

		ptr.value = acs_info[i];
		if (ptr.value)
			uci_set(uci_ctx, &ptr);
		else if (ptr.o)
			uci_delete(uci_ctx, &ptr);
	}

	if (cwmp_load_config())
		return -1;

	cwmp_flag_event("0 BOOTSTRAP", NULL);
	return 0;
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
	uloop_run();
	uloop_done();
}
