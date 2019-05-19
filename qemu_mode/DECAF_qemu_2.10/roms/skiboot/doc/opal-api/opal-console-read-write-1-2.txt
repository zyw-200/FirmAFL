OPAL Console calls
------------------

There are four OPAL calls relating to the OPAL console:

#define OPAL_CONSOLE_WRITE			1
#define OPAL_CONSOLE_READ			2
#define OPAL_CONSOLE_WRITE_BUFFER_SPACE		25
#define OPAL_CONSOLE_FLUSH			117

The OPAL console calls can support multiple consoles. Each console MUST
be represented in the device tree.

A conforming implementation SHOULD have at least one console. It is valid
for it to simply be an in-memory buffer and only support writing.

[TODO: details on device tree specs for console]

OPAL_CONSOLE_WRITE
------------------

Parameters:
	int64_t term_number
	int64_t *length,
        const uint8_t *buffer

Returns:
	OPAL_SUCCESS
	OPAL_PARAMETER - invalid term_number
	OPAL_CLOSED - console device closed
	OPAL_BUSY_EVENT - unable to write any of buffer

term_number is the terminal number as represented in the device tree.
length is a pointer to the length of buffer.

A conformining implementation SHOULD try to NOT do partial writes, although
partial writes and not writing anything are valid.

OPAL_CONSOLE_WRITE_BUFFER_SPACE
-------------------------------

Parameters:
	int64_t term_number
	int64_t *length

Returns:
	OPAL_SUCCESS
	OPAL_PARAMETER - invalid term_number

Returns the available buffer length for OPAL_CONSOLE_WRITE in *length.
This call can be used to help work out if there is sufficient buffer
space to write your full message to the console with OPAL_CONSOLE_WRITE.

OPAL_CONSOLE_READ
-----------------

Parameters:
	int64_t term_number
	int64_t *length
	uint8_t *buffer

Returns:
	OPAL_SUCCESS
	OPAL_PARAMETER - invalid term_number
	OPAL_CLOSED

Use OPAL_POLL_EVENTS for how to determine

OPAL_CONSOLE_FLUSH
------------------

Parameters:
	int64_t term_number

Returns:
	OPAL_SUCCESS
	OPAL_UNSUPPORTED - the console does not implement a flush call
	OPAL_PARAMETER - invalid term_number
	OPAL_PARTIAL - more to flush, call again
	OPAL_BUSY - nothing was flushed this call
