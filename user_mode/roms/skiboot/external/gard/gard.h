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

#include <stdint.h>

#define MAX_PATH_ELEMENTS 10
#define PATH_TYPE_SHIFT 4
#define PATH_ELEMENTS_MASK (0x0F)


enum target_type {
	TYPE_NA			= 0x00000000,
	TYPE_SYS		= 0x00000001,
	TYPE_NODE		= 0x00000002,
	TYPE_DIMM		= 0x00000003,
	TYPE_MEMBUF		= 0x00000004,
	TYPE_PROC		= 0x00000005,
	TYPE_EX			= 0x00000006,
	TYPE_CORE		= 0x00000007,
	TYPE_L2			= 0x00000008,
	TYPE_L3			= 0x00000009,
	TYPE_L4			= 0x0000000A,
	TYPE_MCS		= 0x0000000B,
	TYPE_MBA		= 0x0000000D,
	TYPE_XBUS		= 0x0000000E,
	TYPE_ABUS		= 0x0000000F,
	TYPE_PCI		= 0x00000010,
	TYPE_DPSS		= 0x00000011,
	TYPE_APSS		= 0x00000012,
	TYPE_OCC		= 0x00000013,
	TYPE_PSI		= 0x00000014,
	TYPE_FSP		= 0x00000015,
	TYPE_PNOR		= 0x00000016,
	TYPE_OSC		= 0x00000017,
	TYPE_TODCLK		= 0x00000018,
	TYPE_CONTROL_NODE	= 0x00000019,
	TYPE_OSCREFCLK		= 0x0000001A,
	TYPE_OSCPCICLK		= 0x0000001B,
	TYPE_REFCLKENDPT	= 0x0000001C,
	TYPE_PCICLKENDPT	= 0x0000001D,
	TYPE_NX			= 0x0000001E,
	TYPE_PORE		= 0x0000001F,
	TYPE_PCIESWITCH		= 0x00000020,
	TYPE_CAPP		= 0x00000021,
	TYPE_FSI		= 0x00000022,
	TYPE_TEST_FAIL		= 0x00000023,
	TYPE_LAST_IN_RANGE	= 0x00000024,
};

enum path_type {
	PATH_NA			= 0x00,
	PATH_AFFINITY		= 0x01,
	PATH_PHYSICAL		= 0x02,
	PATH_DEVICE		= 0x03,
	PATH_POWER		= 0x04,
};

struct path_element {
	uint8_t		target_type;
	uint8_t		instance;
} __attribute__((packed));

struct entity_path {
	/* First 4 bits are a path_type enum */
	/* Second 4 bits are the amount of path_elements */
	uint8_t			type_size;
	struct path_element	path_elements[MAX_PATH_ELEMENTS];

} __attribute__((packed));


/* defined by hostboot */
struct gard_record {
	uint32_t		record_id;
	struct entity_path	target_id;
	uint8_t			pad0[3];
	uint32_t		errlog_eid;
	uint8_t			error_type;
	uint8_t			resource_recovery;
	uint8_t			pad1[6];
} __attribute__((packed));

