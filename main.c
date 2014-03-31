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
#define CWMP_INFO_FILE "./examples/cwmp-device.json"
#define CWMP_SESSION_BIN "./session"
#else
#define CWMP_CONFIG_DIR	NULL /* UCI default */
#define CWMP_INFO_FILE "./examples/cwmp-device.json"
#define CWMP_SESSION_BIN "session"
#endif

static struct uci_context *uci_ctx;
static const char *session_path = CWMP_SESSION_BIN;
static const char *devinfo_path = CWMP_INFO_FILE;
static const char *config_path = CWMP_CONFIG_DIR;

static char *acs_info[3];

static bool session_pending;
static int debug_level;

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
	char *ev = cwmp_state_get_events();
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

static int cwmp_load_config(void)
{
	static const struct uci_parse_option opts[] = {
		{ "url", UCI_TYPE_STRING },
		{ "username", UCI_TYPE_STRING },
		{ "password", UCI_TYPE_STRING },
	};
	struct uci_option *tb[3];
	struct uci_ptr ptr = {};
	char buf[32];
	int i, ret = 0;

	strcpy(buf, "cwmp.@cwmp[0]");
	if (uci_lookup_ptr(uci_ctx, &ptr, buf, true)) {
		uci_perror(uci_ctx, "Failed to load configuration");
		return -1;
	}

	uci_parse_section(ptr.s, opts, ARRAY_SIZE(opts), tb);
	if (!tb[0]) {
		fprintf(stderr, "ACS URL not found in config\n");
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(opts); i++) {
		const char *val = tb[i] ? tb[i]->v.string : NULL;

		if (!val && !acs_info[i])
			continue;

		if (val && acs_info[i] && !strcmp(val, acs_info[i]))
			continue;

		free(acs_info[i]);
		acs_info[i] = strdup(val);
		ret = 1;
	}

	return 0;
}

static int usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <options>\n"
		"Options:\n"
		"	-c <path>       Path to UCI config file (default: %s)\n"
		"	-I <file>       Device information file (default: " CWMP_INFO_FILE ")\n"
		"	-d              Increase debug level\n"
		"	-s <path>       Path to session tool\n"
		"\n", prog, CWMP_CONFIG_DIR ? CWMP_CONFIG_DIR : UCI_CONFDIR);
	return 1;
}

int main(int argc, char **argv)
{
	int ch;

	uci_ctx = uci_alloc_context();

	while ((ch = getopt(argc, argv, "c:dI:s:")) != -1) {
		switch(ch) {
		case 'c':
			config_path = optarg;
			break;
		case 'I':
			devinfo_path = optarg;
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
	cwmp_schedule_session();
	uloop_run();
	uloop_done();
}