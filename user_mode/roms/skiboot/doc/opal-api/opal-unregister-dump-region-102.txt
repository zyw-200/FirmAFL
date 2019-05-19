OPAL_UNREGISTER_DUMP_REGION
---------------------------

While OPAL_REGISTER_DUMP_REGION registers a region, OPAL_UNREGISTER_DUMP_REGION
will unregister a region by region ID.

OPAL_UNREGISTER_DUMP_REGION takes one argument: the region ID.

A host OS should check OPAL_UNREGISTER_DUMP_REGION is supported through a call to
OPAL_CHECK_TOKEN.

If OPAL_UNREGISTER_DUMP_REGION is called on a system where the call is present but
unsupported, it will return OPAL_UNSUPPORTED.

BUGS:
Some skiboot versions incorrectly returned OPAL_SUCCESS in the case of
OPAL_UNREGISTER_DUMP_REGION being supported on a platform (so the call was present)
but the call being unsupported for some reason (e.g. on an IBM POWER7 machine).
