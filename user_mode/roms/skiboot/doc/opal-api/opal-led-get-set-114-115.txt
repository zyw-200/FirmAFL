Service Indicators (LEDS)
-------------------------

The service indicator is one element of an overall hardware service strategy
where end user simplicity is a high priority. The goal is system firmware or
operating system code to isolate hardware failures to the failing FRU and
automatically activate the fault indicator associated with the failing FRU.
The end user then needs only to look for the FRU with the active fault
indicator to know which part to replace.

Different types of indicators handled by LED code:
  - System attention indicator (Check log indicator)
	Indicates there is a problem with the system that needs attention.
  - Identify
	Helps the user locate/identify a particular FRU or resource in the
	system.
  - Fault
	Indicates there is a problem with the FRU or resource at the
	location with which the indicator is associated.


LED Design:
-----------
  When it comes to implementation we can classify LEDs into two
  categories:
    1 - Hypervisor (OPAL) controlled LEDs (All identify & fault indicators)
	During boot, we read/cache these LED details in OPAL (location code,
        state, etc). We use cached data to serve read request from FSP/Host.
	And we use SPCN passthrough MBOX command to update these LED state.

    2 - Service processor (FSP) controlled LEDs (System Attention Indicator)
	During boot, we read/cache this LED info using MBOX command. Later
	anytime FSP updates this LED, it sends update system parameter
	notification MBOX command. We use that data to update cached data.
	LED update request is sent via set/reset attn MBOX command.

  LED update request:
    Both FSP and Host will send LED update requests. We have to serialize
    SPCN passthrough command. Hence we maintain local queue.

Note:
  - For more information regarding service indicator refer to PAPR spec
    (Service Indicators chapter).

There are two OPAL calls relating to LED operations.

OPAL_LEDS_GET_INDICATOR
-----------------------
  Returns LED state for the given location code.

OPAL_LEDS_SET_INDICATOR
-----------------------
  Sets LED state for the given location code.

See hw/fsp/fsp-leds.c for more deatails.
