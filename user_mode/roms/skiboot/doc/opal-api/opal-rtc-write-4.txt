OPAL_RTC_WRITE
--------------

OPAL_RTC_WRITE is much like OPAL_RTC_READ in that it can be asynchronous.

If multiple WRITES are issued before the first one completes, subsequent
writes are ignored. There can only be one write in flight at any one time.

Format of the time is the same as for OPAL_RTC_READ.
