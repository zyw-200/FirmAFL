OPAL_CEC_REBOOT and OPAL_CEC_REBOOT2
------------------------------------

#define OPAL_CEC_REBOOT		6
#define OPAL_CEC_REBOOT2	116

There are two opal calls to invoke system reboot.
OPAL_CEC_REBOOT: Used for normal reboot by Linux host.

OPAL_CEC_REBOOT2: Newly introduced to handle abnormal system reboots.
The Linux kernel will make this OPAL call when it has to terminate
abruptly due to an anomalous condition. The kernel will push some system
state context to OPAL, which will in turn push it down to the BMC for
further analysis.

OPAL_CEC_REBOOT
---------------
Syntax:
int64_t opal_cec_reboot(void)

Input parameters:
None.

System reboots normally.

OPAL_CEC_REBOOT2
----------------
Syntax:
int64_t opal_cec_reboot2(uint32_t reboot_type, char *diag)

Input parameters:
	@reboot_type	Type of reboot. (see below)
	@diag		Null-terminated string.

Depending on reboot type, this call will carry out additional steps
before triggering reboot.

Supported reboot types:
----------------------
OPAL_REBOOT_NORMAL = 0
	Behavior is as similar to that of opal_cec_reboot()

OPAL_REBOOT_PLATFORM_ERROR = 1
	Log an error to the BMC and then trigger a system checkstop, using
	the information provided by 'ibm,sw-checkstop-fir' property in the
	device-tree. Post the checkstop trigger, OCC/BMC will collect
	relevant data for error analysis and trigger a reboot.

	In absence of 'ibm,sw-checkstop-fir' device property, this function
	will return with OPAL_UNSUPPORTED and no reboot will be triggered.

Unsupported Reboot type
	For unsupported reboot type, this function will return with
	OPAL_UNSUPPORTED and no reboot will be triggered.
