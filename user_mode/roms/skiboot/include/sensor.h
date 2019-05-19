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

#ifndef __SENSOR_H
#define __SENSOR_H

/*
 * A sensor handler is a four bytes value which identifies a sensor by
 * its resource class (temperature, fans ...), a resource identifier
 * and an attribute number (data, status, ...) :
 *
 *                 Res.
 *     | Attr.  | Class  |   Resource Id  |
 *     |--------|--------|----------------|
 *
 *
 * Helper routines to build or use the sensor handler.
 */
#define sensor_make_handler(sensor_class, sensor_rid, sensor_attr) \
	(((sensor_attr) << 24) | ((sensor_class) & 0xff) << 16 | \
	 ((sensor_rid) & 0xffff))

#define sensor_get_frc(handler)		(((handler) >> 16) & 0xff)
#define sensor_get_rid(handler)		((handler) & 0xffff)
#define sensor_get_attr(handler)	((handler) >> 24)

/*
 * Sensor families
 *
 * This identifier is used to dispatch calls to OPAL_SENSOR_READ to
 * the appropriate component. FSP is the initial family.
 */
#define SENSOR_FSP 0x0
#define SENSOR_DTS 0x80

#define sensor_is_dts(handler)	(sensor_get_frc(handler) & SENSOR_DTS)

/*
 * root node of all sensors : /ibm,opal/sensors
 */
extern struct dt_node *sensor_node;

extern void sensor_init(void);

#endif /* __SENSOR_H */
