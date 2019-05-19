/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <skiboot.h>
#include <i2c.h>
#include <opal.h>
#include <device.h>
#include <opal-msg.h>

static LIST_HEAD(i2c_bus_list);

/* Used to assign OPAL IDs */
static uint32_t i2c_next_bus;

void i2c_add_bus(struct i2c_bus *bus)
{
	bus->opal_id = ++i2c_next_bus;
	dt_add_property_cells(bus->dt_node, "ibm,opal-id", bus->opal_id);

	list_add_tail(&i2c_bus_list, &bus->link);
}

struct i2c_bus *i2c_find_bus_by_id(uint32_t opal_id)
{
	struct i2c_bus *bus;

	list_for_each(&i2c_bus_list, bus, link) {
		if (bus->opal_id == opal_id)
			return bus;
	}
	return NULL;
}

static void opal_i2c_request_complete(int rc, struct i2c_request *req)
{
	uint64_t token = (uint64_t)(unsigned long)req->user_data;

	opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL, token, rc);
	i2c_free_req(req);
}

static int opal_i2c_request(uint64_t async_token, uint32_t bus_id,
			    struct opal_i2c_request *oreq)
{
	struct i2c_bus *bus = NULL;
	struct i2c_request *req;
	int rc;

	if (oreq->flags & OPAL_I2C_ADDR_10)
		return OPAL_UNSUPPORTED;

	bus = i2c_find_bus_by_id(bus_id);
	if (!bus) {
		/**
		 * @fwts-label I2CInvalidBusID
		 * @fwts-advice opal_i2c_request was passed an invalid bus
		 * ID. This has likely come from the OS rather than OPAL
		 * and thus could indicate an OS bug rather than an OPAL
		 * bug.
		 */
		prlog(PR_ERR, "I2C: Invalid 'bus_id' passed to the OPAL\n");
		return OPAL_PARAMETER;
	}

	req = i2c_alloc_req(bus);
	if (!req) {
		/**
		 * @fwts-label I2CFailedAllocation
		 * @fwts-advice OPAL failed to allocate memory for an
		 * i2c_request. This points to an OPAL bug as OPAL ran
		 * out of memory and this should never happen.
		 */
		prlog(PR_ERR, "I2C: Failed to allocate 'i2c_request'\n");
		return OPAL_NO_MEM;
	}

	switch(oreq->type) {
	case OPAL_I2C_RAW_READ:
		req->op = I2C_READ;
		break;
	case OPAL_I2C_RAW_WRITE:
		req->op = I2C_WRITE;
		break;
	case OPAL_I2C_SM_READ:
		req->op = SMBUS_READ;
		req->offset = oreq->subaddr;
		req->offset_bytes = oreq->subaddr_sz;
		break;
	case OPAL_I2C_SM_WRITE:
		req->op = SMBUS_WRITE;
		req->offset = oreq->subaddr;
		req->offset_bytes = oreq->subaddr_sz;
		break;
	default:
		bus->free_req(req);
		return OPAL_PARAMETER;
	}
	req->dev_addr = oreq->addr;
	req->rw_len = oreq->size;
	req->rw_buf = (void *)oreq->buffer_ra;
	req->completion = opal_i2c_request_complete;
	req->user_data = (void *)(unsigned long)async_token;
	req->bus = bus;

	/* Finally, queue the OPAL i2c request and return */
	rc = i2c_queue_req(req);
	if (rc) {
		i2c_free_req(req);
		return rc;
	}

	return OPAL_ASYNC_COMPLETION;
}
opal_call(OPAL_I2C_REQUEST, opal_i2c_request, 3);


