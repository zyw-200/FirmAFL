/* Copyright 2015 IBM Corp.
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

/* This file exists because a bunch of files are built as part of
 * unit tests as well as skiboot and inttypes.h is part of libc rather
 * than gcc, so to get the magic to work when we don't have libc sitting
 * around, we get to rewrite inttypes.h.
 */

#ifndef __SKIBOOT_INTTYPES_H
#define __SKIBOOT_INTTYPES_H

#include <stdint.h>

#ifndef __WORDSIZE
/* If we don't have __WORDSIZE it means we're *certainly* building skiboot
 * which will *ALWAYS* have a word size of 32bits.
 * (unless someone goes and ports skiboot to something that isn't powerpc)
 */
#define __WORDSIZE 32
#endif

#if __WORDSIZE == 64
#define PRIu64 "lu"
#define PRIx64 "lx"
#else
#define PRIu64 "llu"
#define PRIx64 "llx"
#endif

#endif
