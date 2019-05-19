/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <mem-map.h>

ENTRY(boot_entry);
SECTIONS
{
	. = 0;

	.head : {
		KEEP(*(.head))
	}

	. = SPIRA_OFF;
	.spira : {
		KEEP(*(.spira.data))
	}

	. = SPIRAH_OFF;
	.spirah : {
		KEEP(*(.spirah.data))
	}

	. = PROCIN_OFF;
	.procin.data : {
		KEEP(*(.procin.data))
	}

	. = MDST_TABLE_OFF;
	.mdst : {
		KEEP(*(.mdst.data))
	}

	. = CPU_CTL_OFF;
	.cpuctrl : {
		KEEP(*(.cpuctrl.data))
	}

	. = ALIGN(0x10);
	_stext = .;
 	.text : {
		*(.text*)
		*(.sfpr)
	}
	_etext = .;

	.rodata : {
		__rodata_start = .;
		*(.rodata .rodata.*)
		__rodata_end = .;
	}

	.data : {
		/*
		 * A couple of things that need to be 4K aligned and
		 * to reside in their own pages for the sake of TCE
		 * mappings
		 */
		. = ALIGN(0x1000);
		*(.data.memcons);
		. = ALIGN(0x1000);
		*(.data.boot_trace);
		. = ALIGN(0x1000);
		*(.data*)
		*(.force.data)
		*(.toc1)
		*(.branch_lt)
	}

	. = ALIGN(0x10);
	.init : {
		__ctors_start = .;
		*(.ctors)
		*(.init_array)
		__ctors_end = .;
	}
 
	. = ALIGN(0x10);
	.opd : {
		*(.opd)
	}
  
	. = ALIGN(0x100);
	.got : {
		__toc_start = . + 0x8000;
		*(.got)
		*(.toc)
	}

	. = ALIGN(0x10);
	.opal_table : {
		__opal_table_start = .;
		KEEP(*(.opal_table))
		__opal_table_end = .;
	}

	.platforms : {
		__platforms_start = .;
		KEEP(*(.platforms))
		__platforms_end = .;
	}

	/* Do I need to keep these ? */
	.dynsym : { *(.dynsym)	}
	.dynstr : { *(.dynstr)	}

	/* Relocations */
	. = ALIGN(0x10);
	.dynamic : {
		__dynamic_start = .;
		*(.dynamic)
		__dynamic_end = .;
	}

	. = ALIGN(0x10);
	.rela.dyn : {
		__rela_dyn_start = .;
		*(.rela*)
		__rela_dyn_end = .;
	}

	.hash   : { *(.hash)   }
	.dynsym : { *(.dynsym) }
	.dynstr : { *(.dynstr) }

	. = ALIGN(0x10);
	.sym_map : {
		__sym_map_start = . ;
		KEEP(*(.sym_map))
		__sym_map_end = . ;
		KEEP(*(.sym_map))
	}

	/* We locate the BSS at 2M to leave room for the symbol map */
	. = 0x200000;

	_sbss = .;
	.bss : {
		*(.bss*)
	}
	. = ALIGN(0x10000);
	_ebss = .;
	_end = .;

	/* Optional kernel image */
       . = ALIGN(0x10000);
       .builtin_kernel : {
		__builtin_kernel_start = .;
		KEEP(*(.builtin_kernel))
		__builtin_kernel_end = .;
	}

	/* Discards */
	/DISCARD/ : {
		*(.comment)
		*(.interp)
	}
}
