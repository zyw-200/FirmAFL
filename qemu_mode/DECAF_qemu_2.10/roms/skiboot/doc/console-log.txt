SkiBoot Console Log
-------------------

Skiboot maintains a circular textual log buffer in memory.

It can be accessed using any debugging method that can peek at
memory contents. While the debug_descriptor does hold the location
of the memory console, we're pretty keen on keeping its location
static.

Events are logged in the following format:
[timebase,log_level] message

You should use the new prlog() call for any log message and set the
log level/priority appropriately.

printf() is mapped to PR_PRINTF and should be phased out and replaced
with prlog() calls.

See timebase.h for full timebase explanation.

Log level from skiboot.h:
#define PR_EMERG        0
#define PR_ALERT        1
#define PR_CRIT         2
#define PR_ERR          3
#define PR_WARNING      4
#define PR_NOTICE       5
#define PR_PRINTF       PR_NOTICE
#define PR_INFO         6
#define PR_DEBUG        7
#define PR_TRACE        8
#define PR_INSANE       9

The console_log_levels byte in the debug_descriptor controls what
messages are written to any console drivers (e.g. fsp, uart) and
what level is just written to the in memory console (or not at all).

This enables (advanced) users to vary what level of output they want
at runtime in the memory console and through console drivers (fsp/uart)

You can vary two things by poking in the debug descriptor:
a) what log level is printed at all
  e.g. only turn on PR_TRACE at specific points during runtime
b) what log level goes out the fsp/uart console
   defaults to PR_PRINTF
    
We use two 4bit numbers (1 byte) for this in debug descriptor (saving
some space, not needlessly wasting space that we may want in future).
    
The default is 0x75 (7=PR_DEBUG to in memory console, 5=PR_PRINTF to drivers
    
If you write 0x77 you will get debug info on uart/fsp console as
well as in memory. If you write 0x95 you get PR_INSANE in memory but
still only PR_NOTICE through drivers.
    
People who write something like 0x1f will get a very quiet boot indeed.
 


