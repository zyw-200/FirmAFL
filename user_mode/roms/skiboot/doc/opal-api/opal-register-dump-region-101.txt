OPAL_REGISTER_DUMP_REGION
-------------------------

This call is used to register regions of memory for a service processor to capture
when the host crashes.

e.g. if an assert is hit in OPAL, a service processor will copy 

This is an OPTIONAL feature that may be unsupported, the host OS should use an
OPAL_CHECK_TOKEN call to find out if OPAL_REGISTER_DUMP_REGION is supported.

OPAL_REGISTER_DUMP_REGION accepts 3 parameters:
- region ID
- address
- length

There is a range of region IDs that can be used by the host OS. A host OS should
start from OPAL_DUMP_REGION_HOST_END and work down if it wants to add a not well
defined region to dump. Currently the only well defined region is for the host
OS log buffer (e.g. dmesg on linux).

/*
 * Dump region ID range usable by the OS
 */
#define OPAL_DUMP_REGION_HOST_START		0x80
#define OPAL_DUMP_REGION_LOG_BUF		0x80
#define OPAL_DUMP_REGION_HOST_END		0xFF

OPAL_REGISTER_DUMP_REGION will return OPAL_UNSUPPORTED if the call is present but
the system doesn't support registering regions to be dumped.

In the event of being passed an invalid region ID, OPAL_REGISTER_DUMP_REGION will
return OPAL_PARAMETER.

Systems likely have a limit as to how many regions they can support being dumped. If
this limit is reached, OPAL_REGISTER_DUMP_REGION will return OPAL_INTERNAL_ERROR.

BUGS:
Some skiboot versions incorrectly returned OPAL_SUCCESS in the case of
OPAL_REGISTER_DUMP_REGION being supported on a platform (so the call was present)
but the call being unsupported for some reason (e.g. on an IBM POWER7 machine).

See also: OPAL_UNREGISTER_DUMP_REGION
