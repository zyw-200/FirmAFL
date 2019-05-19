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

/* Hostboot runtime interface */
/* Derived from src/include/runtime/interface.h in Hostboot */

#define HOSTBOOT_RUNTIME_INTERFACE_VERSION 1

/** Memory error types defined for memory_error() interface. */
enum MemoryError_t
{
	/** Hardware has reported a solid memory CE that is
	 * correctable, but continues to report errors on subsequent
	 * reads. A second CE on that cache line will result in memory
	 * UE. Therefore, it is advised to migrate off of the address
	 * range as soon as possible. */
	MEMORY_ERROR_CE = 0,

	/** Hardware has reported an uncorrectable error in memory
	 * (memory UE, channel failure, etc). The hypervisor should
	 * migrate any partitions off this address range as soon as
	 * possible. Note that these kind of errors will most likely
	 * result in partition failures. It is advised that the
	 * hypervisor waits some time for PRD to handle hardware
	 * attentions so that the hypervisor will know all areas of
	 * memory that are impacted by the failure. */
	MEMORY_ERROR_UE = 1,
};

/* Capability sets, for get_interface_capabilities */
#define HBRT_CAPS_SET0_COMMON		0
#define HBRT_CAPS_SET1_OPAL		1
#define HBRT_CAPS_SET2_PHYP		2

/* Capability flags */

/**
 * xscom_read and xscom_write return proper return codes on error.
 * Previous implementations may have incorrectly ignored failures.
 */
#define HBRT_CAPS_OPAL_HAS_XSCOM_RC   (1ul << 0)

struct host_interfaces {
	/** Interface version. */
	uint64_t interface_version;

	/** Put a string to the console. */
	void (*puts)(const char*);
	/** Critical failure in runtime execution. */
	void (*assert)(void);

	/** OPTIONAL. Hint to environment that the page may be executed. */
	int (*set_page_execute)(void*);

	/** malloc */
	void *(*malloc)(size_t);
	/** free */
	void (*free)(void*);
	/** realloc */
	void *(*realloc)(void*, size_t);

	/**
	 * @brief Send a PEL to the FSP
	 * @param[in] plid Platform Log identifier
	 * @param[in] data size in bytes
	 * @param[in] pointer to data
	 * @return 0 on success else error code
	 * @platform FSP
	 */
	int (*send_error_log)(uint32_t,uint32_t,void *);

	/**
	 * @brief Scan communication read
	 * @param[in] chip_id (based on devtree defn)
	 * @param[in] address
	 * @param[in] pointer to 8-byte data buffer
	 * @return 0 on success else return code
	 * @platform FSP,OpenPOWER
	 */
	int (*scom_read)(uint64_t, uint64_t, void*);

	/**
	 * @brief Scan communication write
	 * @param[in] chip_id (based on devtree defn)
	 * @param[in] address
	 * @param[in] pointer to 8-byte data buffer
	 * @return 0 on success else return code
	 * @platform FSP,OpenPOWER
	 */
	int (*scom_write)(uint64_t, uint64_t, const void *);

	/**
	 *  @brief Load a LID from PNOR, FSP, etc.
	 *
	 *  @param[in] LID number.
	 *  @param[out] Allocated buffer for LID.
	 *  @param[out] Size of LID (in bytes).
	 *
	 *  @return 0 on success, else RC.
	 *  @platform FSP
	 */
	int (*lid_load)(uint32_t lid, void **buf, size_t *len);

	/**
	 *  @brief Release memory from previously loaded LID.
	 *
	 *  @param[in] Allocated buffer for LID to release.
	 *
	 *  @return 0 on success, else RC.
	 *  @platform FSP
	 */
	int (*lid_unload)(void *buf);

	/**
	 *  @brief Get the address of a reserved memory region by its devtree
	 *  name.
	 *
	 *  @param[in] Devtree name (ex. "ibm,hbrt-vpd-image")
	 *  @param[in] Devtree instance
	 *  @return physical address of region (or NULL).
	 *  @platform FSP,OpenPOWER
	 */
	uint64_t (*get_reserved_mem)(const char *name, uint32_t instance);

	/**
	 * @brief  Force a core to be awake, or clear the force
	 * @param[in] i_core  Core to wake up (pid)
	 * @param[in] i_mode  0=force awake
	 *				1=clear force
	 *				2=clear all previous forces
	 * @return rc  non-zero on error
	 * @platform FSP
	 */
	int (*wakeup)( uint32_t i_core, uint32_t i_mode );

	/**
	 * @brief Delay/sleep for at least the time given
	 * @param[in] seconds
	 * @param[in] nano seconds
	 * @platform FSP,OpenPOWER
	 */
	void (*nanosleep)(uint64_t i_seconds, uint64_t i_nano_seconds);

	/**
	 * @brief Report an OCC error to the host
	 * @param[in] Failing status that identifies the nature of the fail
	 * @param[in] Identifier that specifies the failing part
	 * @platform FSP
	 */
	void (*report_occ_failure)( uint64_t i_status, uint64_t i_partId );

	/**
	 *  @brief Reads the clock value from a POSIX clock.
	 *  @param[in]  i_clkId - The clock ID to read.
	 *  @param[out] o_tp - The timespec struct to store the clock value in.
	 *
	 *  @return 0 or -(errno).
	 *  @retval 0 - SUCCESS.
	 *  @retval -EINVAL - Invalid clock requested.
	 *  @retval -EFAULT - NULL ptr given for timespec struct.
	 *
	 * @platform OpenPOWER
	 */
	int (*clock_gettime)( clockid_t i_clkId, struct timespec* o_tp );

	/**
	 * @brief Read Pnor
	 * @param[in] i_proc: processor Id
	 * @param[in] i_partitionName: name of the partition to read
	 * @param[in] i_offset: offset within the partition
	 * @param[out] o_data: pointer to the data read
	 * @param[in] i_sizeBytes: size of data to read
	 * @retval rc - number of bytes read, or non-zero on error
	 * @platform OpenPOWER
	 */
	int (*pnor_read) ( uint32_t i_proc, const char* i_partitionName,
			uint64_t i_offset, void* o_data, size_t i_sizeBytes );

	/**
	 * @brief Write to Pnor
	 * @param[in] i_proc: processor Id
	 * @param[in] i_partitionName: name of the partition to write
	 * @param[in] i_offset: offset within the partition
	 * @param[in] i_data: pointer to the data to write
	 * @param[in] i_sizeBytes: size of data to write
	 * @retval rc - number of bytes written, or non-zero on error
	 * @platform OpenPOWER
	 */
	int (*pnor_write) ( uint32_t i_proc, const char* i_partitionName,
			uint64_t i_offset, void* i_data, size_t i_sizeBytes );


	/**
	 * i2c master description: chip, engine and port packed into
	 * a single 64-bit argument
	 *
	 * ---------------------------------------------------
	 * |         chip         |  reserved  |  eng | port |
         * |         (32)         |    (16)    |  (8) | (8)  |
	 * ---------------------------------------------------
	 */
#define HBRT_I2C_MASTER_CHIP_SHIFT	32
#define HBRT_I2C_MASTER_CHIP_MASK	(0xfffffffful << 32)
#define HBRT_I2C_MASTER_ENGINE_SHIFT	8
#define HBRT_I2C_MASTER_ENGINE_MASK	(0xfful << 8)
#define HBRT_I2C_MASTER_PORT_SHIFT	0
#define HBRT_I2C_MASTER_PORT_MASK	(0xfful)

	/**
	 * @brief Read data from an i2c device
	 * @param[in] i_master - Chip/engine/port of i2c bus
	 * @param[in] i_devAddr - I2C address of device
	 * @param[in] i_offsetSize - Length of offset (in bytes)
	 * @param[in] i_offset - Offset within device to read
	 * @param[in] i_length - Number of bytes to read
	 * @param[out] o_data - Data that was read
	 * @return 0 on success else return code
	 * @platform OpenPOWER
	 */
	int (*i2c_read)( uint64_t i_master, uint16_t i_devAddr,
			 uint32_t i_offsetSize, uint32_t i_offset,
			 uint32_t i_length, void* o_data );

	/**
	 * @brief Write data to an i2c device
	 * @param[in] i_master - Chip/engine/port of i2c bus
	 * @param[in] i_devAddr - I2C address of device
	 * @param[in] i_offsetSize - Length of offset (in bytes)
	 * @param[in] i_offset - Offset within device to write
	 * @param[in] i_length - Number of bytes to write
	 * @param[in] Data to write
	 * @return 0 on success else return code
	 * @platform OpenPOWER
	 */
	int (*i2c_write)( uint64_t i_master, uint16_t i_devAddr,
			  uint32_t i_offsetSize, uint32_t i_offset,
			  uint32_t i_length, void* i_data );

	/**
	 * Perform an IPMI transaction
	 * @param[in] netfn The IPMI netfn byte
	 * @param[in] cmd The IPMI cmd byte
	 * @param[in] tx_buf The IPMI packet to send to the host
	 * @param[in] tx_size The number of bytes, to send
	 * @param[in] rx_buf A buffer to be populated with the IPMI
	 *		response.
	 * @param[inout] rx_size The allocated size of the rx buffer on
	 *		input, updated to the size of the response on output.
	 *		This should always begin with the IPMI completion
	 *		code.
	 */
	int (*ipmi_msg)(uint8_t netfn, uint8_t cmd,
			void *tx_buf, size_t tx_size,
			void *rx_buf, size_t *rx_size);


	/**
	 * @brief Hardware has reported a memory error. This function requests
	 * the hypervisor to remove the all addresses within the address range
	 * given (including endpoints) from the available memory space.
	 *
	 * It is understood that the hypervisor may not be able to immediately
	 * deallocate the memory because it may be in use by a partition.
	 * Therefore, the hypervisor should cache all requests and deallocate
	 * the memory once it has been freed.
	 *
	 * @param  i_startAddr The beginning address of the range.
	 * @param  i_endAddr   The end address of the range.
	 * @param  i_errorType See enum MemoryError_t.
	 *
	 * @return 0 if the request is successfully received. Any value other
	 *	than 0 on failure. The hypervisor should cache the request and
	 *	return immediately. It should not wait for the request to be
	 *	applied. See note above.
	 */
	int (*memory_error)( uint64_t i_startAddr, uint64_t i_endAddr,
					  enum MemoryError_t i_errorType );

	/**
	 * @brief Query the prd infrastructure for interface capabilities.
	 * @param[in] i_set The set of capabilites to retrieve
	 *
	 * @return a bitmask containing the relevant HBRT_CAPS_* for
	 *	this implementation and the specified set.
	 */
	uint64_t (*get_interface_capabilities)(uint64_t i_set);

	/* Reserve some space for future growth. */
	void (*reserved[31])(void);
};

struct runtime_interfaces {
	/** Interface version. */
	uint64_t interface_version;

	/**
	 * @brief Execute CxxTests that may be contained in the image.
	 *
	 * @param[in] - Pointer to CxxTestStats structure for results reporting.
	 */
	void (*cxxtestExecute)(void *);

	/**
	 * @brief Get a list of lids numbers of the lids known to HostBoot
	 *
	 * @param[out] o_num - the number of lids in the list
	 * @return a pointer to the list
	 * @platform FSP
	 */
	const uint32_t * (*get_lid_list)(size_t * o_num);

	/**
	 * @brief Load OCC Image and common data into mainstore, also setup OCC
	 * BARSs
	 *
	 * @param[in] i_homer_addr_phys - The physical mainstore address of the
	 *	start of the HOMER image
	 * @param[in] i_homer_addr_va - Virtual memory address of the HOMER
	 *	image
	 * @param[in] i_common_addr_phys - The physical mainstore address
	 *	of the OCC common area.
	 * @param[in] i_common_addr_va - Virtual memory address of the common
	 *	area
	 * @param[in] i_chip - The HW chip id (XSCOM chip ID)
	 * @return 0 on success else return code
	 * @platform FSP
	 */
	int (*occ_load)(uint64_t i_homer_addr_phys,
			 uint64_t i_homer_addr_va,
			 uint64_t i_common_addr_phys,
			 uint64_t i_common_addr_va,
			 uint64_t i_chip);

	/**
	 * @brief Start OCC on all chips, by module
	 *
	 *  @param[in] i_chip - Array of functional HW chip ids
	 *  @Note The caller must include a complete modules worth of chips
	 *  @param[in] i_num_chips - Number of chips in the array
	 *  @return 0 on success else return code
	 *  @platform FSP
	 */
	int (*occ_start)(uint64_t* i_chip, size_t i_num_chips);

	/**
	 * @brief Stop OCC hold OCCs in reset
	 *
	 *  @param[in] i_chip - Array of functional HW chip ids
	 *  @Note The caller must include a complete modules worth of chips
	 *  @param[in] i_num_chips - Number of chips in the array
	 *  @return 0 on success else return code
	 *  @platform FSP
	 */
	int (*occ_stop)(uint64_t* i_chip, size_t i_num_chips);

	/**
	 * @brief Notify HTMGT that an OCC has an error to report
	 *
	 * @details  When an OCC has encountered an error that it wants to
	 *		   be reported, this interface will be called to trigger
	 *		   HTMGT to collect and commit the error.
	 *
	 * @param[i] i_chipId - Id of processor with failing OCC
	 * @platform OpenPower
	 */
	void (*process_occ_error) (uint64_t i_chipId);

	/**
	 *  @brief Enable chip attentions
	 *
	 *  @return 0 on success else return code
	 *  @platform OpenPower
	 */
	int (*enable_attns)(void);

	/**
	 *  @brief Disable chip attentions
	 *
	 *  @return 0 on success else return code
	 *  @platform OpenPower
	 */
	int (*disable_attns)(void);

	/**
	 *  @brief handle chip attentions
	 *
	 *  @param[in] i_proc - processor chip id at attention XSCOM chip id
	 *	based on devtree defn
	 *  @param[in] i_ipollStatus - processor chip Ipoll status
	 *  @param[in] i_ipollMask   - processor chip Ipoll mask
	 *  @return 0 on success else return code
	 *  @platform OpenPower
	 */
	int (*handle_attns)(uint64_t i_proc, uint64_t i_ipollStatus,
			uint64_t i_ipollMask);

	/**
	 * @brief Notify HTMGT that an OCC has failed and needs to be reset
	 *
	 * @details  When BMC detects an OCC failure that requires a reset,
	 * this interface will be called to trigger the OCC reset.  HTMGT
	 * maintains a reset count and if there are additional resets
	 * available, the OCCs get reset/reloaded.  If the recovery attempts
	 * have been exhauseted or the OCC fails to go active, an unrecoverable
	 * error will be logged and the system will remain in safe mode.
	 *
	 * @param[in]  i_chipId  ChipID which identifies the OCC reporting an
	 *	error
	 * @platform OpenPOWER
	 */
	void (*process_occ_reset)(uint64_t  i_chipId);

	/**
	 * @brief Change the OCC state
	 *
	 * @details  This is a blocking call that will change the OCC state.
	 * The OCCs will only actuate (update processor frequency/ voltages)
	 * when in Active state.  The OCC will only be monitoring/observing
	 * when in Observation state.
	 *
	 * @note When the OCCs are initially started, the state will
	 * default to Active.  If the state is changed to Observation, that
	 * state will be retained until the next IPL. (If the OCC would get
	 * reset, it would return to the last requested state)
	 *
	 * @param[in]  i_occActivation  set to true to move OCC to Active state
	 *	or false to move OCC to Observation state
	 *
	 * @return  0 on success, or return code if the state did not change.
	 * @platform OpenPower
	 */
	int (*enable_occ_actuation)(bool i_occActivation);

	/**
	 * @brief	Apply a set of attribute overrides
	 *
	 * @param[in]	pointer to binary override data
	 * @param[in]	length of override data (bytes)
	 * @returns	0 on success, or return code if the command failed
	 *
	 * @platform	OpenPower
	 */
	int (*apply_attr_override)(uint8_t *i_data, size_t size);

	/**
	 * @brief	Send a pass-through command to HTMGT
	 *
	 * @details	This is a blocking call that will send a command to
	 *		HTMGT.
	 *
	 * @note	If o_rspLength is returned with a non-zero value, the
	 *		data at the o_rspData should be dumped to stdout in a
	 *		hex dump format.
	 * @note	The maximum response data returned will be 4096 bytes
	 *
	 * @param[in]	i_cmdLength	number of bytes in pass-thru command data
	 * @param[in]	*i_cmdData	pointer to pass-thru command data
	 * @param[out]	*o_rspLength	pointer to number of bytes returned in
	 *				o_rspData
	 * @param[out]	*o_rspData	pointer to a 4096 byte buffer that will
	 *				contain the response data from the command
	 *
	 * @returns	0 on success, or return code if the command failed
	 * @platform	OpenPower
	 */
	int (*mfg_htmgt_pass_thru)(uint16_t i_cmdLength, uint8_t *i_cmdData,
				   uint16_t *o_rspLength, uint8_t *o_rspData);

	/**
	 * @brief	Execute an arbitrary command inside hostboot runtime
	 * @param[in]	Number of arguments (standard C args)
	 * @param[in]	Array of argument values (standard C args)
	 * @param[out]	Response message (NULL terminated), memory allocated
	 *		by hbrt, if o_outString is NULL then no response will
	 *		be sent
	 * @return	0 on success, else error code
	 */
	int (*run_command)(int argc, const char **argv, char **o_outString);

	/* Reserve some space for future growth. */
	void (*reserved[29])(void);
};
