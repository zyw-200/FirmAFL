OPAL_CEC_POWER_DOWN
-------------------

#define OPAL_CEC_POWER_DOWN			5

int64 opal_cec_power_down(uint64 request)

Arguments:

  uint64 request values as follows:
    0 - Power down normally
    1 - Power down immediately

This OPAL call requests OPAL to power down the system. The exact difference
between a normal and immediate shutdown is platform specific.

Current Linux kernels just use power down normally (0). It is valid for a
platform to only support some types of power down operations.

Return Values:
OPAL_SUCCESS: the power down was updated successful
OPAL_BUSY: unable to power down, try again later
OPAL_PARAMETER: a parameter was incorrect
OPAL_INTERNAL_ERROR: hal code sent incorrect data to hardware device
OPAL_UNSUPPORTED: this platform does not support being powered off.
