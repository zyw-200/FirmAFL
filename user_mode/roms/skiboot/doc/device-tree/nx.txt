Nest (NX) Accelerator Coprocessor
---------------------------------

The NX coprocessor is present in P7+ or later processors.  Each NX node
represents a unique NX coprocessor.  The nodes are located under an
xscom node, as:

/xscom@<xscom_addr>/nx@<nx_addr>

With unique xscom and nx addresses.  Their compatible node contains
"ibm,power-nx".


NX 842 Coprocessor
------------------

This is the memory compression coprocessor, which uses the IBM proprietary
842 compression algorithm and format.  Each nx node contains an 842 engine.

ibm,842-coprocessor-type	: CT value common to all 842 coprocessors
ibm,842-coprocessor-instance	: CI value unique to all 842 coprocessors

Access to the coprocessor requires using the ICSWX instruction, which uses
a specific format including a Coprocessor Type (CT) and Coprocessor Instance
(CI) value to address each request to the right coprocessor.  The driver should
use the CT and CI values for a particular node to communicate with it.  For
all 842 coprocessors in the system, the CT value will (should) be the same,
while each will have a different CI value.  The driver can use CI 0 to allow
the hardware to automatically select which coprocessor instance to use.


NX RNG Coprocessor
------------------

This is the Random Number Generator (RNG) coprocessor, which is a part
of each NX coprocessor.  Each node represents a unique RNG coprocessor.
Its nodes are not under the main nx node, they are located at:

/hwrng@<addr>		: RNG at address <addr>
ibm,chip-id		: chip id where the RNG is
reg			: address of the register to read from

Each read from the RNG register will provide a new random number.


