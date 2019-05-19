OPAL_PCI_GET_POWER_STATE
---------------------------

Get PCI slot power state

Parameters:
	uint64_t id: PCI slot ID
	uint64_t data: memory buffer pointer for power state

Calling:

Retrieve PCI slot's power state. The retrieved power state is stored
in buffer pointed by @data.

Return Codes:

OPAL_SUCCESS - PCI slot's power state is retrieved successfully
OPAL_PARAMETER - The indicated PCI slot isn't found
OPAL_UNSUPPORTED - Power state retrieval not supported on the PCI slot
