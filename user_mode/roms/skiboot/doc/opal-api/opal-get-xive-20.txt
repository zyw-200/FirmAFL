OPAL_GET_XIVE
-------------

#define OPAL_GET_XIVE				20

WARNING: following documentation is from old sources, and is possibly
not representative of OPALv3 as implemented by skiboot. This should be
used as a starting point for full documentation.

The host calls this function to return the POWER XIVE server and priority
values currently set in a PHB XIVE.

    The phb_id parameter is the value from the PHB node ibm,opal-phbid
    property.

    The xive_number is the index of an XIVE that corresponds to a particular
    interrupt

    the server_number returns the server (processor) that is set in this XIVE

    the priority returns the interrupt priority value that is set in this XIVE

    This call returns the server and priority numbers from within the XIVE
    specified by the XIVE_number.

