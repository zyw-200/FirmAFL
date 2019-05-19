OPAL_READ_TPO and OPAL_WRITE_TPO
--------------------------------

TPO is a Timed Power On facility.

It is an OPTIONAL part of the OPAL spec.

If a platform supports Timed Power On (TPO), the RTC node in the device tree (itself under the "ibm,opal" node will have the has-tpo property:

rtc {
     compatible = "ibm,opal-rtc";
     has-tpo;
};

If the "has-tpo" proprety is *NOT* present then OPAL does *NOT* support TPO.
