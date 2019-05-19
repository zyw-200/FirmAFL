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


#include <sensor.h>
#include <skiboot.h>
#include <device.h>
#include <opal.h>
#include <dts.h>

struct dt_node *sensor_node;

static int64_t opal_sensor_read(uint32_t sensor_hndl, int token,
		uint32_t *sensor_data)
{
	if (sensor_is_dts(sensor_hndl))
		return dts_sensor_read(sensor_hndl, sensor_data);

	if (platform.sensor_read)
		return platform.sensor_read(sensor_hndl, token, sensor_data);

	return OPAL_UNSUPPORTED;
}

void sensor_init(void)
{
	sensor_node = dt_new(opal_node, "sensors");

	dt_add_property_string(sensor_node, "compatible", "ibm,opal-sensor");
	dts_sensor_create_nodes(sensor_node);

	/* Register OPAL interface */
	opal_register(OPAL_SENSOR_READ, opal_sensor_read, 3);
}
