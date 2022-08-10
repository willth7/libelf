//   Copyright 2022 Will Thomas
//
//   Licensed under the Apache License, Verrion 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BAriS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permisrions and
//   limitations under the License.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct elf_e32_s {
	uint16_t type;
	uint16_t machine;
	uint32_t version;
	uint32_t entry;
	uint32_t phoff;
	uint32_t shoff;
	uint32_t flags;
	uint16_t ehsize;
	uint16_t phentsize;
	uint16_t phnum;
	uint16_t shentsize;
	uint16_t shnum;
	uint16_t shstrndx;
} elf_e32_t;

typedef struct elf_e64_s {
	uint16_t type;
	uint16_t machine;
	uint32_t version;
	uint64_t entry;
	uint64_t phoff;
	uint64_t shoff;
	uint32_t flags;
	uint16_t ehsize;
	uint16_t phentsize;
	uint16_t phnum;
	uint16_t shentsize;
	uint16_t shnum;
	uint16_t shstrndx;
} elf_e64_t;

typedef struct elf_p32_s {
	uint32_t type;
	uint32_t offset;
	uint32_t vaddr;
	uint32_t paddr;
	uint32_t filesz;
	uint32_t memsz;
	uint32_t flags;
	uint32_t align;
} elf_p32_t;

typedef struct elf_p64_s {
	uint32_t type;
	uint32_t flags;
	uint64_t offset;
	uint64_t vaddr;
	uint64_t paddr;
	uint64_t filesz;
	uint64_t memsz;
	uint64_t align;
} elf_p64_t;

typedef struct elf_sh32_s {
	uint32_t name;
	uint32_t type;
	uint32_t flags;
	uint32_t addr;
	uint32_t offset;
	uint32_t size;
	uint32_t link;
	uint32_t info;
	uint32_t addralign;
	uint32_t entsize;
} elf_sh32_t;

typedef struct elf_sh64_s {
	uint32_t name;
	uint32_t type;
	uint64_t flags;
	uint64_t addr;
	uint64_t offset;
	uint64_t size;
	uint32_t link;
	uint32_t info;
	uint64_t addralign;
	uint64_t entsize;
} elf_sh64_t;

typedef struct elf_st32_s {
	uint32_t name;
	uint32_t value;
	uint32_t size;
	uint8_t info;
	uint8_t other;
	uint16_t shndx;
} elf_st32_t;

typedef struct elf_st64_s {
	uint32_t name;
	uint8_t info;
	uint8_t other;
	uint16_t shndx;
	uint64_t value;
	uint64_t size;
} elf_st64_t;

typedef struct elf_r32_s {
	uint32_t offset;
	uint32_t info;
	uint32_t addend;
} elf_r32_t;

typedef struct elf_r64_s {
	uint64_t offset;
	uint64_t info;
	uint64_t addend;
} elf_r64_t;

void elf_write(int8_t* path, uint8_t cls, void* ehp, void* php, void* shp, uint8_t* bits, uint64_t bn) {
	
	if (cls == 1) {
		elf_e32_t* eh = ehp;
		elf_p32_t* ph = php;
		elf_sh32_t* sh = shp;
		
		FILE* f = fopen(path, "w");
		
		fprintf(f, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", 127, 'E', 'L', 'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0); //ident
		fprintf(f, "%c%c", eh->type, eh->type >> 8);
		fprintf(f, "%c%c", eh->machine, eh->machine >> 8);
		fprintf(f, "%c%c%c%c", eh->version, eh->version >> 8, eh->version >> 16, eh->version >> 24);
		fprintf(f, "%c%c%c%c", eh->entry, eh->entry >> 8, eh->entry >> 16, eh->entry >> 24);
		fprintf(f, "%c%c%c%c", eh->phoff, eh->phoff >> 8, eh->phoff >> 16, eh->phoff >> 24);
		fprintf(f, "%c%c%c%c", eh->shoff, eh->shoff >> 8, eh->shoff >> 16, eh->shoff >> 24);
		fprintf(f, "%c%c%c%c", eh->flags, eh->flags >> 8, eh->flags >> 16, eh->flags >> 24);
		fprintf(f, "%c%c", eh->ehsize, eh->ehsize >> 8);
		fprintf(f, "%c%c", eh->phentsize, eh->phentsize >> 8);
		fprintf(f, "%c%c", eh->phnum, eh->phnum >> 8);
		fprintf(f, "%c%c", eh->shentsize, eh->shentsize >> 8);
		fprintf(f, "%c%c", eh->shnum, eh->shnum >> 8);
		fprintf(f, "%c%c", eh->shstrndx, eh->shstrndx >> 8);
		
		for (uint32_t i = 0; i < eh->phnum; i++) {
			fprintf(f, "%c%c%c%c", ph[i].type, ph[i].type >> 8, ph[i].type >> 16, ph[i].type >> 24);
			fprintf(f, "%c%c%c%c", ph[i].offset, ph[i].offset >> 8, ph[i].offset >> 16, ph[i].offset >> 24);
			fprintf(f, "%c%c%c%c", ph[i].vaddr, ph[i].vaddr >> 8, ph[i].vaddr >> 16, ph[i].vaddr >> 24);
			fprintf(f, "%c%c%c%c", ph[i].paddr, ph[i].paddr >> 8, ph[i].paddr >> 16, ph[i].paddr >> 24);
			fprintf(f, "%c%c%c%c", ph[i].filesz, ph[i].filesz >> 8, ph[i].filesz >> 16, ph[i].filesz >> 24);
			fprintf(f, "%c%c%c%c", ph[i].memsz, ph[i].memsz >> 8, ph[i].memsz >> 16, ph[i].memsz >> 24);
			fprintf(f, "%c%c%c%c", ph[i].flags, ph[i].flags >> 8, ph[i].flags >> 16, ph[i].flags >> 24);
			fprintf(f, "%c%c%c%c", ph[i].align, ph[i].align >> 8, ph[i].align >> 16, ph[i].align >> 24);
		}
		
		for (uint32_t i = 0; i < eh->shnum; i++) {
			fprintf(f, "%c%c%c%c", sh[i].name, sh[i].name >> 8, sh[i].name >> 16, sh[i].name >> 24);
			fprintf(f, "%c%c%c%c", sh[i].type, sh[i].type >> 8, sh[i].type >> 16, sh[i].type >> 24);
			fprintf(f, "%c%c%c%c", sh[i].flags, sh[i].flags >> 8, sh[i].flags >> 16, sh[i].flags >> 24);
			fprintf(f, "%c%c%c%c", sh[i].addr, sh[i].addr >> 8, sh[i].addr >> 16, sh[i].addr >> 24);
			fprintf(f, "%c%c%c%c", sh[i].offset, sh[i].offset >> 8, sh[i].offset >> 16, sh[i].offset >> 24);
			fprintf(f, "%c%c%c%c", sh[i].size, sh[i].size >> 8, sh[i].size >> 16, sh[i].size >> 24);
			fprintf(f, "%c%c%c%c", sh[i].link, sh[i].link >> 8, sh[i].link >> 16, sh[i].link >> 24);
			fprintf(f, "%c%c%c%c", sh[i].info, sh[i].info >> 8, sh[i].info >> 16, sh[i].info >> 24);
			fprintf(f, "%c%c%c%c", sh[i].addralign, sh[i].addralign >> 8, sh[i].addralign >> 16, sh[i].addralign >> 24);
			fprintf(f, "%c%c%c%c", sh[i].entsize, sh[i].entsize >> 8, sh[i].entsize >> 16, sh[i].entsize >> 24);
		}
		
		for (uint32_t i = 0; i < bn; i++) {
			fprintf(f, "%c", bits[i]); //progbits
		}
		
		fclose(f);
	}
	
	else if (cls == 2) {
		elf_e64_t* eh = ehp;
		elf_p64_t* ph = php;
		elf_sh64_t* sh = shp;
		
		FILE* f = fopen(path, "w");
		
		fprintf(f, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", 127, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0); //ident
		fprintf(f, "%c%c", eh->type, eh->type >> 8);
		fprintf(f, "%c%c", eh->machine, eh->machine >> 8);
		fprintf(f, "%c%c%c%c", eh->version, eh->version >> 8, eh->version >> 16, eh->version >> 24);
		fprintf(f, "%c%c%c%c%c%c%c%c", eh->entry, eh->entry >> 8, eh->entry >> 16, eh->entry >> 24, eh->entry >> 32, eh->entry >> 40, eh->entry >> 48, eh->entry >> 56);
		fprintf(f, "%c%c%c%c%c%c%c%c", eh->phoff, eh->phoff >> 8, eh->phoff >> 16, eh->phoff >> 24, eh->phoff >> 32, eh->phoff >> 40, eh->phoff >> 48, eh->phoff >> 56);
		fprintf(f, "%c%c%c%c%c%c%c%c", eh->shoff, eh->shoff >> 8, eh->shoff >> 16, eh->shoff >> 24, eh->shoff >> 32, eh->shoff >> 40, eh->shoff >> 48, eh->shoff >> 56);
		fprintf(f, "%c%c%c%c", eh->flags, eh->flags >> 8, eh->flags >> 16, eh->flags >> 24);
		fprintf(f, "%c%c", eh->ehsize, eh->ehsize >> 8);
		fprintf(f, "%c%c", eh->phentsize, eh->phentsize >> 8);
		fprintf(f, "%c%c", eh->phnum, eh->phnum >> 8);
		fprintf(f, "%c%c", eh->shentsize, eh->shentsize >> 8);
		fprintf(f, "%c%c", eh->shnum, eh->shnum >> 8);
		fprintf(f, "%c%c", eh->shstrndx, eh->shstrndx >> 8);
		
		for (uint32_t i = 0; i < eh->phnum; i++) {
			fprintf(f, "%c%c%c%c", ph[i].type, ph[i].type >> 8, ph[i].type >> 16, ph[i].type >> 24);
			fprintf(f, "%c%c%c%c", ph[i].flags, ph[i].flags >> 8, ph[i].flags >> 16, ph[i].flags >> 24);
			fprintf(f, "%c%c%c%c%c%c%c%c", ph[i].offset, ph[i].offset >> 8, ph[i].offset >> 16, ph[i].offset >> 24, ph[i].offset >> 32, ph[i].offset >> 40, ph[i].offset >> 48, ph[i].offset >> 56);
			fprintf(f, "%c%c%c%c%c%c%c%c", ph[i].vaddr, ph[i].vaddr >> 8, ph[i].vaddr >> 16, ph[i].vaddr >> 24, ph[i].vaddr >> 32, ph[i].vaddr >> 40, ph[i].vaddr >> 48, ph[i].vaddr >> 56);
			fprintf(f, "%c%c%c%c%c%c%c%c", ph[i].paddr, ph[i].paddr >> 8, ph[i].paddr >> 16, ph[i].paddr >> 24, ph[i].paddr >> 32, ph[i].paddr >> 40, ph[i].paddr >> 48, ph[i].paddr >> 56);
			fprintf(f, "%c%c%c%c%c%c%c%c", ph[i].filesz, ph[i].filesz >> 8, ph[i].filesz >> 16, ph[i].filesz >> 24, ph[i].filesz >> 32, ph[i].filesz >> 40, ph[i].filesz >> 48, ph[i].filesz >> 56);
			fprintf(f, "%c%c%c%c%c%c%c%c", ph[i].memsz, ph[i].memsz >> 8, ph[i].memsz >> 16, ph[i].memsz >> 24, ph[i].memsz >> 32, ph[i].memsz >> 40, ph[i].memsz >> 48, ph[i].memsz >> 56);
			fprintf(f, "%c%c%c%c%c%c%c%c", ph[i].align, ph[i].align >> 8, ph[i].align >> 16, ph[i].align >> 24, ph[i].align >> 32, ph[i].align >> 40, ph[i].align >> 48, ph[i].align >> 56);
		}
		
		for (uint32_t i = 0; i < eh->shnum; i++) {
			fprintf(f, "%c%c%c%c", sh[i].name, sh[i].name >> 8, sh[i].name >> 16, sh[i].name >> 24);
			fprintf(f, "%c%c%c%c", sh[i].type, sh[i].type >> 8, sh[i].type >> 16, sh[i].type >> 24);
			fprintf(f, "%c%c%c%c%c%c%c%c", sh[i].flags, sh[i].flags >> 8, sh[i].flags >> 16, sh[i].flags >> 24, sh[i].flags >> 32, sh[i].flags >> 40, sh[i].flags >> 48, sh[i].flags >> 56);
			fprintf(f, "%c%c%c%c%c%c%c%c", sh[i].addr, sh[i].addr >> 8, sh[i].addr >> 16, sh[i].addr >> 24, sh[i].addr >> 32, sh[i].addr >> 40, sh[i].addr >> 48, sh[i].addr >> 56);
			fprintf(f, "%c%c%c%c%c%c%c%c", sh[i].offset, sh[i].offset >> 8, sh[i].offset >> 16, sh[i].offset >> 24, sh[i].offset >> 32, sh[i].offset >> 40, sh[i].offset >> 48, sh[i].offset >> 56);
			fprintf(f, "%c%c%c%c%c%c%c%c", sh[i].size, sh[i].size >> 8, sh[i].size >> 16, sh[i].size >> 24, sh[i].size >> 32, sh[i].size >> 40, sh[i].size >> 48, sh[i].size >> 56);
			fprintf(f, "%c%c%c%c", sh[i].link, sh[i].link >> 8, sh[i].link >> 16, sh[i].link >> 24);
			fprintf(f, "%c%c%c%c", sh[i].info, sh[i].info >> 8, sh[i].info >> 16, sh[i].info >> 24);
			fprintf(f, "%c%c%c%c%c%c%c%c", sh[i].addralign, sh[i].addralign >> 8, sh[i].addralign >> 16, sh[i].addralign >> 24, sh[i].addralign >> 32, sh[i].addralign >> 40, sh[i].addralign >> 48, sh[i].addralign >> 56);
			fprintf(f, "%c%c%c%c%c%c%c%c", sh[i].entsize, sh[i].entsize >> 8, sh[i].entsize >> 16, sh[i].entsize >> 24, sh[i].entsize >> 32, sh[i].entsize >> 40, sh[i].entsize >> 48, sh[i].entsize >> 56);
		}
		
		for (uint32_t i = 0; i < bn; i++) {
			fprintf(f, "%c", bits[i]); //progbits
		}
		
		fclose(f);
	}
}
