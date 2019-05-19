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

/*
 * Handle FSP EPOW event notifications
 */

#ifndef __FSP_EPOW_H
#define __FSP_EPOW_H

/* FSP based EPOW event notifications */
#define EPOW_NORMAL	0x00	/* panel status normal */
#define EPOW_EX1	0x01	/* panel status extended 1 */
#define EPOW_EX2	0x02	/* Panel status extended 2 */

/* EPOW reason code notifications */
#define EPOW_ON_UPS	1	/* System on UPS */
#define EPOW_TMP_AMB	2	/* Over ambient temperature */
#define EPOW_TMP_INT	3	/* Over internal temperature */

#endif
