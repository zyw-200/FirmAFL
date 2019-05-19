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

#include <skiboot.h>
#include <cec.h>
#include <p7ioc.h>
#include <interrupts.h>
#include <opal-api.h>

/*
 * Note: This file os only used on P7/P7+
 */
#define MAX_IO_HUBS	0x80

static struct io_hub *cec_iohubs[MAX_IO_HUBS];

struct io_hub *cec_get_hub_by_id(uint32_t hub_id)
{
	if (hub_id >= MAX_IO_HUBS)
		return NULL;
	return cec_iohubs[hub_id];
}

void cec_register(struct io_hub *hub)
{
	assert(hub->hub_id < MAX_IO_HUBS);
	cec_iohubs[hub->hub_id] = hub;
}

void cec_reset(void)
{
	unsigned int i;

	/* Reset IO Hubs */
	for (i = 0; i < MAX_IO_HUBS; i++) {
		if (!cec_iohubs[i] || !cec_iohubs[i]->ops->reset)
			continue;
		cec_iohubs[i]->ops->reset(cec_iohubs[i]);
	}
}

/* This was only supported by p5ioc, which was dropped */
static int64_t opal_pci_set_hub_tce_memory(uint64_t hub_id,
					   uint64_t tce_mem_addr __unused,
					   uint64_t tce_mem_size __unused)
{
	struct io_hub *hub = cec_get_hub_by_id(hub_id);

	if (!hub)
		return OPAL_PARAMETER;

	return OPAL_UNSUPPORTED;
}
opal_call(OPAL_PCI_SET_HUB_TCE_MEMORY, opal_pci_set_hub_tce_memory, 3);

static int64_t opal_pci_get_hub_diag_data(uint64_t hub_id,
					  void *diag_buffer,
					  uint64_t diag_buffer_len)
{
	struct io_hub *hub = cec_get_hub_by_id(hub_id);

	if (!hub)
		return OPAL_PARAMETER;

	if (!hub->ops->get_diag_data)
		return OPAL_UNSUPPORTED;

	return hub->ops->get_diag_data(hub, diag_buffer, diag_buffer_len);
}
opal_call(OPAL_PCI_GET_HUB_DIAG_DATA, opal_pci_get_hub_diag_data, 3);
