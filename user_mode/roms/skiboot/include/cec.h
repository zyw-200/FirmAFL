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

#ifndef __CEC_H
#define __CEC_H

#include <stdint.h>

/* This represent an IO Hub and contains the function pointers
 * for the IO Hub related OPAL ops and other internal functions
 */

struct io_hub;

struct io_hub_ops {
	/* OPAL_PCI_GET_HUB_DIAG_DATA */
	int64_t (*get_diag_data)(struct io_hub *hub, void *diag_buffer,
				 uint64_t diag_buffer_len);

	/* Called on fast reset */
	void (*reset)(struct io_hub *hub);
};

struct io_hub {
	uint32_t			hub_id;
	const struct io_hub_ops		*ops;
};

extern struct io_hub *cec_get_hub_by_id(uint32_t hub_id);

extern void cec_reset(void);
extern void cec_register(struct io_hub *hub);

#endif /* __CEC_H */
