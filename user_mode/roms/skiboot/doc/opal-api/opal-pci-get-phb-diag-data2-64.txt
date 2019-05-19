OPAL_PCI_GET_PHB_DIAG_DATA2
---------------------------
Get PCI diagnostic data from a given PHB

Parameters:
	uint64_t phb_id: the ID of the PHB you want to retrieve data from
	void *diag_buffer: an allocated buffer to store diag data in
	uint64_t diag_buffer_len: size in bytes of the diag buffer

Calling:

Retrieve the PHB's diagnostic data.  The diagnostic data is stored in the
buffer pointed by @diag_buffer.  Different PHB versions will store different
diagnostics, defined in include/opal-api.h as "struct OpalIo<PHBVer>ErrorData".

OPAL_PCI_GET_PHB_DIAG_DATA is deprecated and OPAL_PCI_GET_PHB_DIAG_DATA2 should
be used instead.

Return Codes:

OPAL_SUCCESS - Diagnostic data has been retrieved and stored successfully
OPAL_PARAMETER - The given buffer is too small to store the diagnostic data
OPAL_HARDWARE - The PHB is in a broken state and its data cannot be retreived
OPAL_UNSUPPORTED - Diagnostic data is not implemented for this PHB type
