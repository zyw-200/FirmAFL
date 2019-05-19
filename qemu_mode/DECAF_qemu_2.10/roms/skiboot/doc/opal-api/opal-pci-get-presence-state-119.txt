OPAL_PCI_GET_PRESENCE_STATE
---------------------------

Get PCI slot presence state

Parameters:
	uint64_t id: PCI slot ID
	uint64_t data: memory buffer pointer for presence state

Calling:

Retrieve PCI slot's presence state. The detected presence means there are
adapters inserted to the PCI slot. Otherwise, the PCI slot is regarded as
an empty one. The typical use is to ensure there are adapters existing
before probing the PCI slot in PCI hot add path. The retrieved presence
state is stored in buffer pointed by @data.

Return Codes:

OPAL_SUCCESS - PCI slot's presence state is retrieved successfully
OPAL_PARAMETER - The indicated PCI slot isn't found
OPAL_UNSUPPORTED - Presence retrieval not supported on the PCI slot
