#ifndef BLOB_HELPERS_H
#define BLOB_HELPERS_H

#include "../ucwmp.h"

#include <libubox/blobmsg.h>
#include <string.h>
#include <inttypes.h>

static inline const char * blob_any_to_string(struct blob_attr *val,
					char *buf, unsigned len)
{
	const enum blobmsg_type t = blobmsg_type(val);

	switch (t) {
	case BLOBMSG_TYPE_STRING:
		buf = blobmsg_data(val);
		break;
	case BLOBMSG_TYPE_INT32:
		snprintf(buf, len, "%d", blobmsg_get_u32(val));
		break;
	case BLOBMSG_TYPE_INT64:
		snprintf(buf, len, "%" PRId64, blobmsg_get_u64(val));
		break;
	case BLOBMSG_TYPE_BOOL:
		buf = blobmsg_get_bool(val) ? "true" : "false";
		break;
	default:
		err("unknown type %d\n", t);
		break;
	}
	return buf;
}

#endif
