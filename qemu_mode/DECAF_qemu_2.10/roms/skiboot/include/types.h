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

#ifndef __TYPES_H
#define __TYPES_H
#include <ccan/short_types/short_types.h>
#include <ccan/endian/endian.h>

/* These are currently just for clarity, but we could apply sparse. */
typedef beint16_t __be16;
typedef beint32_t __be32;
typedef beint64_t __be64;

#endif /* __TYPES_H */

