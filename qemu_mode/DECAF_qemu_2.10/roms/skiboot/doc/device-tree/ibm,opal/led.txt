Service Indicators (LEDS)
-------------------------

The 'leds' node under 'ibm,opal' lists service indicators available in the
system and their capabilities.

leds {
	compatible = "ibm,opal-v3-led";
	phandle = <0x1000006b>;
	linux,phandle = <0x1000006b>;
	led-mode = "lightpath";

	U78C9.001.RST0027-P1-C1 {
		led-types = "identify", "fault";
		phandle = <0x1000006f>;
		linux,phandle = <0x1000006f>;
	};
	...
	...
};

'compatible' property describes LEDs compatibility.

'led-mode' property describes service indicator mode (lightpath/guidinglight).

Each node under 'leds' node describes location code of FRU/Enclosure.

The properties under each node:

  led-types : Supported indicators (attention/identify/fault).

These LEDs can be accessed through OPAL_LEDS_{GET/SET}_INDICATOR interfaces.
Refer to doc/opal-api/opal-led-get-set-114-115.txt for interface details.
