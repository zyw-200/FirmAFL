OPAL_INT_EOI
------------

static int64_t opal_xive_eoi(uint32_t xirr)

Not yet implemented.

Modelled on the H_EOI PAPR call.

This can return a positive value, which means more interrupts
are queued for that CPU/priority and must be fetched as the XIVE is not
guaranteed to assert the CPU external interrupt line again until the
pending queue for the current priority has been emptied.

For P9 and above systems where host doesn't know about interrupt controller.
An OS can instead make OPAL calls for XICS emulation.

For an OS to use this OPAL call, an "ibm,opal-intc" compatible device must
exist in the device tree. If OPAL does not create such a device, the host
OS MUST NOT use this call.
