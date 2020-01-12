#ifndef CWMP_UBUS_H
#define CWMP_UBUS_H

#include "../ucwmp.h"

#include <libubus.h>
#include <libubox/blobmsg.h>

#define err_ubus(ubus_rc, fmt, args...) \
	err(fmt ": %s\n", ##args, ubus_strerror(ubus_rc))

#endif
