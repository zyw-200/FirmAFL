OPAL_INT_GET_XIRR
-----------------

int64_t opal_xive_get_xirr(uint32_t *out_xirr, bool just_poll)

Not yet implemented.

Modelled on the PAPR call.

For P9 and above systems where host doesn't know about interrupt controller.
An OS can instead make OPAL calls for XICS emulation.

For an OS to use this OPAL call, an "ibm,opal-intc" compatible device must
exist in the device tree. If OPAL does not create such a device, the host
OS MUST NOT use this call.
