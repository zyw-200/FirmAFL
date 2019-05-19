OPAL_REINIT_CPUS
----------------

static int64_t opal_reinit_cpus(uint64_t flags);

This OPAL call reinitializes some bit of CPU state across *ALL* CPUs.
Consequently, all CPUs must be in OPAL for this call to succeed (either
at boot time or after OPAL_RETURN_CPU is called)

Arguments:
Currently, possible flags are:
enum {
	OPAL_REINIT_CPUS_HILE_BE	= (1 << 0),
	OPAL_REINIT_CPUS_HILE_LE	= (1 << 1),
};

Extra flags may be added in the future, so other bits *must* be 0.

On POWER7 CPUs, only OPAL_REINIT_CPUS_HILE_BE is supported. All other
flags will return OPAL_UNSUPPORTED.

On POWER8 CPUs, only OPAL_REINIT_CPUS_HILE_BE and OPAL_REINIT_CPUS_HILE_LE
are support and other bits *MUST NOT* be set.

On POWER9 CPUs, other flags may be supported in the future.

Returns:
- OPAL_SUCCESS
- OPAL_UNSUPPORTED
