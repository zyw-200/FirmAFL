OPAL_GET_DEVICE_TREE
--------------------

Get device sub-tree

Parameters:
	uint32_t phandle: root device node phandle of the device sub-tree
	uint64_t buf: FDT blob buffer or NULL
	uint64_t len: length of the FDT blob buffer

Calling:

Retrieve device sub-tree. The root node's phandle is identified by @phandle.
The typical use is for the kernel to update its device tree following a change
in hardware (e.g. PCI hotplug).

Return Codes:

FDT blob size - returned FDT blob buffer size when @buf is NULL
OPAL_SUCCESS - FDT blob is created successfully
OPAL_PARAMETER - invalid argument @phandle or @len
OPAL_INTERNAL_ERROR - failure creating FDT blob when calculating its size
OPAL_NO_MEM - not enough room in buffer for device sub-tree
OPAL_EMPTY - failure creating FDT blob
