ibm,opal/power-mgt device tree entries
--------------------------------------

All available CPU idle states are listed in ibm,cpu-idle-state-names

For example:
ibm,cpu-idle-state-names = "nap", "fastsleep_", "winkle";

The idle states are characterized by latency and residency
numbers which determine the breakeven point for entry into them. The
latency is a measure of the exit overhead from the idle state and
residency is the minimum amount of time that a CPU must be predicted
to be idle so as to reap the powersavings from entering into that idle
state.

These numbers are made use of by the cpuidle governors in the kernel to
arrive at the appropriate idle state that a CPU must enter into when there is
no work to be done. The values in ibm,cpu-idle-state-latencies-ns are the
the measured latency numbers for the idle states. The residency numbers have
been arrived at experimentally after ensuring that the performance of latency
sensitive workloads do not regress while allowing deeper idle states to be
entered into during low load situations. The kernel is expected to use these
values for optimal power efficiency.
 
ibm,cpu-idle-state-residency-ns = <0x1 0x2 0x3>
ibm,cpu-idle-state-latencies-ns = <0x1 0x2 0x3>


ibm,cpu-idle-state-pmicr ibm,cpu-idle-state-pmicr-mask
------------------------------------------------------
In POWER8, idle states sleep and winkle have 2 modes- fast and deep. In fast
mode, idle state puts the core into threshold voltage whereas deep mode
completely turns off the core. Choosing fast vs deep mode for an idle state
can be done either via PM_GP1 scom or by writing to PMICR special register.
If using the PMICR path to choose fast/deep mode then ibm,cpu-idle-state-pmicr
and ibm,cpu-idle-state-pmicr-mask properties expose relevant PMICR bits and
values for corresponding idle states.


ibm,cpu-idle-state-psscr ibm,cpu-idle-state-psscr-mask
------------------------------------------------------
In POWER ISA v3, there is a common instruction 'stop' to enter any idle state
and SPR PSSCR is used to specify which idle state needs to be entered upon
executing stop instruction. Properties ibm,cpu-idle-state-psscr and
ibm,cpu-idle-state-psscr-mask expose the relevant PSSCR bits and values for
corresponding idle states.


ibm,cpu-idle-state-flags
------------------------
These flags are used to describe the characteristics of the idle states like
the kind of core state loss caused. These flags are used by the kernel to
save/restore appropriate context while using the idle states.


ibm,pstate-ids
--------------

This property lists the available pstate identifiers, as signed 32-bit
big-endian values. While the identifiers are somewhat arbitrary, these define
the order of the pstates in other ibm,pstate-* properties.


ibm,pstate-frequencies-mhz
--------------------------

This property lists the frequency, in MHz, of each of the pstates listed in the
ibm,pstate-ids file. Each frequency is a 32-bit big-endian word.


ibm,pstate-max ibm,pstate-min ibm,pstate-nominal
------------------------------------------------

These properties give the maximum, minimum and nominal pstate values, as an id
specified in the ibm,pstate-ids file.


ibm,pstate-vcss ibm,pstate-vdds
-------------------------------

These properties list a voltage-identifier of each of the pstates listed in
ibm,pstate-ids for the Vcs and Vdd values used for that pstate. Each VID is a
single byte.

ibm,pstate-ultra-turbo ibm,pstate-turbo
---------------------------------------

These properties are added when ultra-turbo(WOF) is enabled. These properties
give the max turbo and max ultra-turbo pstate.

ibm,pstate-core-max
-------------------

This property is added when ultra_turbo(WOF) is enabled. This property gives
the list of max pstate for each 'n' number of active cores in the chip.

