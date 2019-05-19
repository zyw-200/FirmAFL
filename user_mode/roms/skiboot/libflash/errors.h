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
#ifndef __LIBFLASH_ERRORS_H
#define __LIBFLASH_ERRORS_H

#define FLASH_ERR_MALLOC_FAILED		1
#define FLASH_ERR_CHIP_UNKNOWN		2
#define FLASH_ERR_PARM_ERROR		3
#define FLASH_ERR_ERASE_BOUNDARY	4
#define FLASH_ERR_WREN_TIMEOUT		5
#define FLASH_ERR_WIP_TIMEOUT		6
#define FLASH_ERR_BAD_PAGE_SIZE		7
#define FLASH_ERR_VERIFY_FAILURE	8
#define FLASH_ERR_4B_NOT_SUPPORTED	9
#define FLASH_ERR_CTRL_CONFIG_MISMATCH	10
#define FLASH_ERR_CHIP_ER_NOT_SUPPORTED	11
#define FLASH_ERR_CTRL_CMD_UNSUPPORTED	12
#define FLASH_ERR_CTRL_TIMEOUT		13
#define FLASH_ERR_ECC_INVALID		14
#define FLASH_ERR_BAD_READ		15

#endif /* __LIBFLASH_ERRORS_H */
