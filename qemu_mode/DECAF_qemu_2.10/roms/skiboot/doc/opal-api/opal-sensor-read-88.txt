OPAL_SENSOR_READ
----------------

The OPAL sensor call reads a sensor data using a unique handler to
identity the targeted sensor.


This call can be asynchronous, when a message needs to be sent to a
service processor for example.  In this case, the call will return
OPAL_ASYNC_COMPLETION and the token parameter will be used to wait for
the completion of the request.


Parameters:
	uint32_t sensor_handler
	int	 token
	uint32_t *sensor_data


Return values:
	OPAL_SUCCESS
	OPAL_PARAMETER - invalid sensor handler
	OPAL_UNSUPPORTED - plateform does not support reading sensors.

in case of communication with the FSP on IBM systems

	OPAL_ASYNC_COMPLETION - a request was sent and an async completion will
		be triggered with the @token argument
	OPAL_PARTIAL - the request completed but the data returned is invalid
	OPAL_BUSY_EVENT - a previous request is still pending
	OPAL_NO_MEM - allocation failed
	OPAL_INTERNAL_ERROR - communication failure with the FSP
	OPAL_HARDWARE - FSP is not available
