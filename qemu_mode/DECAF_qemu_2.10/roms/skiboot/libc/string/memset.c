/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include "string.h"

#define CACHE_LINE_SIZE 128

void *
memset(void *dest, int c, size_t size)
{
	unsigned char *d = (unsigned char *)dest;

#if defined(__powerpc__) || defined(__powerpc64__)
	if (size > CACHE_LINE_SIZE && c==0) {
		while ((unsigned long long)d % CACHE_LINE_SIZE) {
			*d++ = (unsigned char)c;
			size--;
		}
		while (size >= CACHE_LINE_SIZE) {
			asm volatile ("dcbz 0,%0\n" : : "r"(d) : "memory");
			d+= CACHE_LINE_SIZE;
			size-= CACHE_LINE_SIZE;
		}
	}
#endif

	while (size >= 8 && c == 0) {
		*((unsigned long long*)d) = 0ULL;
		d+=8;
		size-=8;
	}

	while (size-- > 0) {
		*d++ = (unsigned char)c;
	}

	return dest;
}
