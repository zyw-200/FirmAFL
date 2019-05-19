/* Copyright 2013-2015 IBM Corp.
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
 * limitations under the License.
 */

#ifndef __DTS_H
#define __DTS_H

#include <stdint.h>

extern int64_t dts_sensor_read(uint32_t sensor_hndl, uint32_t *sensor_data);
extern bool dts_sensor_create_nodes(struct dt_node *sensors);

#endif /* __DTS_H */
