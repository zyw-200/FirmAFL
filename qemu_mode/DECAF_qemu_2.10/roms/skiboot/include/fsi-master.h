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

#ifndef __FSI_MASTER_H
#define __FSI_MASTER_H

/*
 * Definition of the MFSI masters
 */
#define MFSI_cMFSI0	0
#define MFSI_cMFSI1	1
#define MFSI_hMFSI0	2

extern int64_t mfsi_read(uint32_t chip, uint32_t mfsi, uint32_t port,
			 uint32_t fsi_addr, uint32_t *data);

extern int64_t mfsi_write(uint32_t chip, uint32_t mfsi, uint32_t port,
			  uint32_t fsi_addr, uint32_t data);

extern void mfsi_init(void);

#endif /* __FSI_MASTER_H */

