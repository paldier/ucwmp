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
#ifndef __UCWMP_SESSION_UTILS_H
#define __UCWMP_SESSION_UTILS_H

#ifndef BITS_PER_LONG
#define BITS_PER_LONG (8 * sizeof(unsigned long))
#endif

#define BITFIELD_SIZE(_n) (((_n) + (BITS_PER_LONG - 1)) / BITS_PER_LONG)

static inline void bitfield_set(unsigned long *bits, int bit)
{
	bits[bit / BITS_PER_LONG] |= (1UL << (bit % BITS_PER_LONG));
}

static inline bool bitfield_test(unsigned long *bits, int bit)
{
	return !!(bits[bit / BITS_PER_LONG] & (1UL << (bit % BITS_PER_LONG)));
}

#endif
