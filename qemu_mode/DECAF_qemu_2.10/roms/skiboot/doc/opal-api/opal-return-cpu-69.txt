OPAL_RETURN_CPU
---------------

int64_t opal_return_cpu(void);

When OPAL first starts the host, all secondary CPUs are spinning in OPAL.
To start them, one must call OPAL_START_CPU (you may want to OPAL_REINIT_CPU
to set the HILE bit first).

In cases where you need OPAL to do something for you across all CPUs, such
as OPAL_REINIT_CPU, (on some platforms) a firmware update or get the machine
back into a similar state as to when the host OS was started (e.g. for kexec)
you may also need to return control of the CPU to OPAL.


Returns:
- this call does not return. You need to OPAL_START_CPU.
