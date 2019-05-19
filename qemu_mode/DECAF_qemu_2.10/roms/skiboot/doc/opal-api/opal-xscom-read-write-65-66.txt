OPAL_XSCOM_READ and OPAL_XSCOM_WRITE
------------------------------------

These low level calls will read/write XSCOM values directly.

They should only be used by low level manufacturing/debug tools.
"Normal" host OS kernel code should not know about XSCOM.

each takes three parameters:

int xscom_read(uint32_t partid, uint64_t pcb_addr, uint64_t *val)
int xscom_write(uint32_t partid, uint64_t pcb_addr, uint64_t val)

Returns:
	OPAL_SUCCESS
	OPAL_HARDWARE if operation failed
	OPAL_WRONG_STATE if CPU is asleep
