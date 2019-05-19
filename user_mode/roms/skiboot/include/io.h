/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __IO_H
#define __IO_H

#ifndef __ASSEMBLY__

#include <compiler.h>
#include <stdint.h>
#include <processor.h>
#include <ccan/endian/endian.h>

/*
 * IO access functions
 *
 * __in_beXX() / __out_beXX() : non-byteswap, no barrier
 * in_beXX() / out_beXX()     : non-byteswap, barrier
 * in_leXX() / out_leXX()     : byteswap, barrier
 */

static inline uint8_t __in_8(const volatile uint8_t *addr)
{
	uint8_t val;
	asm volatile("lbzcix %0,0,%1" :
		     "=r"(val) : "r"(addr), "m"(*addr) : "memory");
	return val;
}

static inline uint8_t in_8(const volatile uint8_t *addr)
{
	sync();
	return __in_8(addr);
}

static inline uint16_t __in_be16(const volatile uint16_t *addr)
{
	uint16_t val;
	asm volatile("lhzcix %0,0,%1" :
		     "=r"(val) : "r"(addr), "m"(*addr) : "memory");
	return val;
}

static inline uint16_t in_be16(const volatile uint16_t *addr)
{
	sync();
	return __in_be16(addr);
}

static inline uint16_t in_le16(const volatile uint16_t *addr)
{
	return bswap_16(in_be16(addr));
}

static inline uint32_t __in_be32(const volatile uint32_t *addr)
{
	uint32_t val;
	asm volatile("lwzcix %0,0,%1" :
		     "=r"(val) : "r"(addr), "m"(*addr) : "memory");
	return val;
}

static inline uint32_t in_be32(const volatile uint32_t *addr)
{
	sync();
	return __in_be32(addr);
}

static inline uint32_t in_le32(const volatile uint32_t *addr)
{
	return bswap_32(in_be32(addr));
}

static inline uint64_t __in_be64(const volatile uint64_t *addr)
{
	uint64_t val;
	asm volatile("ldcix %0,0,%1" :
		     "=r"(val) : "r"(addr), "m"(*addr) : "memory");
	return val;
}

static inline uint64_t in_be64(const volatile uint64_t *addr)
{
	sync();
	return __in_be64(addr);
}

static inline uint64_t in_le64(const volatile uint64_t *addr)
{
	return bswap_64(in_be64(addr));
}

static inline void __out_8(volatile uint8_t *addr, uint8_t val)
{
	asm volatile("stbcix %0,0,%1"
		     : : "r"(val), "r"(addr), "m"(*addr) : "memory");
}

static inline void out_8(volatile uint8_t *addr, uint8_t val)
{
	sync();
	return __out_8(addr, val);
}

static inline void __out_be16(volatile uint16_t *addr, uint16_t val)
{
	asm volatile("sthcix %0,0,%1"
		     : : "r"(val), "r"(addr), "m"(*addr) : "memory");
}

static inline void out_be16(volatile uint16_t *addr, uint16_t val)
{
	sync();
	return __out_be16(addr, val);
}

static inline void out_le16(volatile uint16_t *addr, uint16_t val)
{
	out_be16(addr, bswap_16(val));
}

static inline void __out_be32(volatile uint32_t *addr, uint32_t val)
{
	asm volatile("stwcix %0,0,%1"
		     : : "r"(val), "r"(addr), "m"(*addr) : "memory");
}

static inline void out_be32(volatile uint32_t *addr, uint32_t val)
{
	sync();
	return __out_be32(addr, val);
}

static inline void out_le32(volatile uint32_t *addr, uint32_t val)
{
	out_be32(addr, bswap_32(val));
}

static inline void __out_be64(volatile uint64_t *addr, uint64_t val)
{
	asm volatile("stdcix %0,0,%1"
		     : : "r"(val), "r"(addr), "m"(*addr) : "memory");
}

static inline void out_be64(volatile uint64_t *addr, uint64_t val)
{
	sync();
	return __out_be64(addr, val);
}

static inline void out_le64(volatile uint64_t *addr, uint64_t val)
{
	out_be64(addr, bswap_64(val));
}

/* Assistant to macros used to access PCI config space */
#define in_le8	in_8
#define out_le8	out_8

#endif /* __ASSEMBLY__ */

#endif /* __IO_H */
