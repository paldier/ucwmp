#ifndef __UCWMP_UTIL_H
#define __UCWMP_UTIL_H

#define _v_enum(_prefix, _name, ...) _prefix ## _ ## _name,
#define _v_param_name(_prefix, _name, ...) [_prefix ## _ ## _name] = #_name,
#define _v_blobmsg_string(_prefix, _name, ...)		\
		[_prefix ## _ ## _name] = {		\
			.name = #_name,			\
			.type = BLOBMSG_TYPE_STRING	\
		},


#define _v(_mode, ...) _v_##_mode (__VA_ARGS__)

#define CWMP_ENUM(_prefix, _fields) \
	_fields(enum, _prefix)

#define CWMP_PARAM_NAMES(_prefix, _fields) \
	_fields(param_name, _prefix)

#define CWMP_BLOBMSG_STRING(_prefix, _fields) _fields(blobmsg_string, _prefix)

#endif
