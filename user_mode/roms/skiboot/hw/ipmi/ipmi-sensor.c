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

#include <device.h>
#include <ipmi.h>
#include <opal.h>
#include <skiboot.h>
#include <string.h>

#define IPMI_WRITE_SENSOR		(1 << 0)

#define FW_PROGRESS_SENSOR_TYPE	0x0F
#define BOOT_COUNT_SENSOR_TYPE	0xC3

#define MAX_IPMI_SENSORS 255
static int16_t sensors[MAX_IPMI_SENSORS];

struct set_sensor_req {
	u8 sensor_number;
	u8 operation;
	u8 sensor_reading;
	u8 assertion_mask[2];
	u8 deassertion_mask[2];
	u8 event_data[3];
};

uint8_t ipmi_get_sensor_number(uint8_t sensor_type)
{
	assert(sensor_type < MAX_IPMI_SENSORS);
	return sensors[sensor_type];
}

int ipmi_set_boot_count(void)
{
	struct set_sensor_req req;
	struct ipmi_msg *msg;
	int boot_count_sensor = sensors[BOOT_COUNT_SENSOR_TYPE];

	if (!ipmi_present())
		return OPAL_CLOSED;

	if (boot_count_sensor < 0) {
		prlog(PR_DEBUG, "IPMI: boot count set but not present\n");
		return OPAL_HARDWARE;
	}

	memset(&req, 0, sizeof(req));

	req.sensor_number = boot_count_sensor;
	req.operation = IPMI_WRITE_SENSOR;
	req.sensor_reading = 0x00;
	req.assertion_mask[0] = 0x02;

	msg = ipmi_mkmsg_simple(IPMI_SET_SENSOR_READING, &req, sizeof(req));
	if (!msg)
		return OPAL_HARDWARE;

	printf("IPMI: Resetting boot count on successful boot\n");

	return ipmi_queue_msg(msg);
}

int ipmi_set_fw_progress_sensor(uint8_t state)
{
	struct ipmi_msg *msg;
	struct set_sensor_req request;
	int fw_sensor_num = sensors[FW_PROGRESS_SENSOR_TYPE];

	if (!ipmi_present())
		return OPAL_CLOSED;

	if (fw_sensor_num < 0) {
		prlog(PR_DEBUG, "IPMI: fw progress set but not present\n");
		return OPAL_HARDWARE;
	}

	memset(&request, 0, sizeof(request));

	request.sensor_number = fw_sensor_num;
	request.operation = 0xa0; /* Set event data bytes, assertion bits */
	request.assertion_mask[0] = 0x04; /* Firmware progress offset */
	request.event_data[0] = 0xc2;
	request.event_data[1] = state;

	prlog(PR_INFO, "IPMI: setting fw progress sensor %02x to %02x\n",
			request.sensor_number, request.event_data[1]);

	msg = ipmi_mkmsg_simple(IPMI_SET_SENSOR_READING, &request,
			sizeof(request));
	if (!msg)
		return OPAL_HARDWARE;

	return ipmi_queue_msg(msg);
}

void ipmi_sensor_init(void)
{
	const struct dt_property *type_prop, *num_prop;
	uint8_t num, type;
	struct dt_node *n;

	memset(sensors, -1, sizeof(sensors));

	dt_for_each_compatible(dt_root, n, "ibm,ipmi-sensor") {
		type_prop = dt_find_property(n, "ipmi-sensor-type");
		if (!type_prop) {
			prerror("IPMI: sensor doesn't have ipmi-sensor-type\n");
			continue;
		}

		num_prop = dt_find_property(n, "reg");
		if (!num_prop) {
			prerror("IPMI: sensor doesn't have reg property\n");
			continue;
		}
		num = (uint8_t)dt_property_get_cell(num_prop, 0);
		type = (uint8_t)dt_property_get_cell(type_prop, 0);
		assert(type < MAX_IPMI_SENSORS);
		sensors[type] = num;
	}
}
