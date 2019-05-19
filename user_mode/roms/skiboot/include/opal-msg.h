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


#ifndef __OPALMSG_H
#define __OPALMSG_H

#include <opal.h>

/*
 * It dictates the number of asynchronous tokens available at the kernel,
 * ideally the value matches to the number of modules using async
 * infrastructure, but not necessarily the same..
 */
#define OPAL_MAX_ASYNC_COMP	8

int _opal_queue_msg(enum opal_msg_type msg_type, void *data,
		    void (*consumed)(void *data), size_t num_params,
		    const u64 *params);

#define opal_queue_msg(msg_type, data, cb, ...) \
	_opal_queue_msg(msg_type, data, cb, \
			sizeof((u64[]) {__VA_ARGS__})/sizeof(u64), \
			(u64[]) {__VA_ARGS__});

void opal_init_msg(void);

#endif /* __OPALMSG_H */
