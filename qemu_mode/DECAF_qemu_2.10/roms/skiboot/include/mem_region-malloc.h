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

#ifndef __MEM_REGION_MALLOC_H
#define __MEM_REGION_MALLOC_H

#include <compiler.h>

#define __loc2(line)    #line
#define __loc(line)	__loc2(line)
#define __location__	__FILE__ ":" __loc(__LINE__)

void *__malloc(size_t size, const char *location) __warn_unused_result;
void *__zalloc(size_t size, const char *location) __warn_unused_result;
void *__realloc(void *ptr, size_t size, const char *location) __warn_unused_result;
void __free(void *ptr, const char *location);
void *__memalign(size_t boundary, size_t size, const char *location) __warn_unused_result;

#define malloc(size) __malloc(size, __location__)
#define zalloc(size) __zalloc(size, __location__)
#define realloc(ptr, size) __realloc(ptr, size, __location__)
#define free(ptr) __free(ptr, __location__)
#define memalign(boundary, size) __memalign(boundary, size, __location__)

void *__local_alloc(unsigned int chip, size_t size, size_t align,
		    const char *location) __warn_unused_result;
#define local_alloc(chip_id, size, align)	\
	__local_alloc((chip_id), (size), (align), __location__)

#endif /* __MEM_REGION_MALLOC_H */
