ENTRY(_start)
SECTIONS
{
	.text :
	{
		_start = .;
		*(.text)
	}

	. = ALIGN(4096);
	.data :
	{
		*(.rodata*)
		*(.data*)
		*(.sdata*)
		*(.got2)
	}

	. = ALIGN(4096);
	.bss :
	{
		_edata  =  .;
		__bss_start = .;
		*(.sbss)
		*(.bss)
		*(COMMON)
		_end = . ;
	}
}
