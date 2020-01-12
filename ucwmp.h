#ifndef UCWMP_H
#define UCWMP_H

#include <stdio.h>

#define err(fmt, args...) \
	fprintf(stderr, "%s: " fmt, __FUNCTION__, ##args)

#endif
