#ifndef STRNCPYT_H
#define STRNCPYT_H

#include <string.h>

/* strncpy with always 0 terminated string
 */
static inline void strncpyt(char *dst, const char *src, size_t n)
{
	strncpy(dst, src, n - 1);
	dst[n - 1] = 0;
}

#endif
