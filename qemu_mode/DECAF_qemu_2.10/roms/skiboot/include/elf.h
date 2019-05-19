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

#ifndef __ELF_H
#define __ELF_H

#include <stdint.h>

/* Generic ELF header */
struct elf_hdr {
	uint32_t ei_ident;
#define ELF_IDENT	0x7F454C46
	uint8_t ei_class;
#define ELF_CLASS_32	1
#define ELF_CLASS_64	2
	uint8_t ei_data;
#define ELF_DATA_LSB	1
#define ELF_DATA_MSB	2
	uint8_t ei_version;
	uint8_t ei_pad[9];
	uint16_t e_type;
	uint16_t e_machine;
#define ELF_MACH_PPC32	0x14
#define ELF_MACH_PPC64	0x15
	uint32_t e_version;
};

/* 64-bit ELF header */
struct elf64_hdr {
	uint32_t ei_ident;
	uint8_t ei_class;
	uint8_t ei_data;
	uint8_t ei_version;
	uint8_t ei_pad[9];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

/* 64-bit ELF program header */
struct elf64_phdr {
	uint32_t p_type;
#define ELF_PTYPE_LOAD	1
	uint32_t p_flags;
#define ELF_PFLAGS_R	0x4
#define ELF_PFLAGS_W	0x2
#define ELF_PFLAGS_X	0x1
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* 64-bit ELF section header */
struct elf64_shdr {
	uint32_t sh_name;
	uint32_t sh_type;
	uint64_t sh_flags;
#define ELF_SFLAGS_X	0x4
#define ELF_SFLAGS_A	0x2
#define ELF_SFLAGS_W	0x1
	uint64_t sh_addr;
	uint64_t sh_offset;
	uint64_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint64_t sh_addralign;
	int64_t sh_entsize;
};

/* Some relocation related stuff used in relocate.c */
struct elf64_dyn {
	int64_t	 d_tag;
#define DT_NULL	 	0
#define DT_RELA	 	7
#define DT_RELASZ	8
#define DT_RELAENT	9
#define DT_RELACOUNT	0x6ffffff9
	uint64_t d_val;
};

struct elf64_rela {
	uint64_t	r_offset;
	uint64_t	r_info;
#define ELF64_R_TYPE(info)		((info) & 0xffffffffu)
	int64_t		r_addend;
};

/* relocs we support */
#define R_PPC64_RELATIVE	22

/* 32-bit ELF header */
struct elf32_hdr {
	uint32_t ei_ident;
	uint8_t ei_class;
	uint8_t ei_data;
	uint8_t ei_version;
	uint8_t ei_pad[9];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint32_t e_entry;
	uint32_t e_phoff;
	uint32_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

/* 32-bit ELF program header*/
struct elf32_phdr {
	uint32_t p_type;
	uint32_t p_offset;
	uint32_t p_vaddr;
	uint32_t p_paddr;
	uint32_t p_filesz;
	uint32_t p_memsz;
	uint32_t p_flags;
	uint32_t p_align;
};


#endif /* __ELF_H */
