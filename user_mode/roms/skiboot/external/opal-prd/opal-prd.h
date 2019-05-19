/* Copyright 2015 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * imitations under the License.
 */
#ifndef OPAL_PRD_H
#define OPAL_PRD_H

#include <syslog.h>

#define pr_debug(fmt, ...) pr_log(LOG_DEBUG, fmt, ## __VA_ARGS__)

void pr_log(int priority, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#endif /* OPAL_PRD_H */

