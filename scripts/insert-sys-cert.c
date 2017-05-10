/* Write the contents of the <certfile> into kernel symbol system_extra_cert
 *
 * Copyright (C) IBM Corporation, 2015
 *
 * Author: Mehmet Kayaalp <mkayaalp@linux.vnet.ibm.com>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 *
 * Usage: insert-sys-cert [-s <System.map> -b <vmlinux> -c <certfile>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <gelf.h>
#include <linux/types.h>

#define CERT_SYM  "system_extra_cert"
#define USED_SYM  "system_extra_cert_used"
#define LSIZE_SYM "system_certificate_list_size"

#define info(format, args...) fprintf(stdout, "INFO:    " format, ## args)
#define warn(format, args...) fprintf(stdout, "WARNING: " format, ## args)
#define  err(format, args...) fprintf(stderr, "ERROR:   " format, ## args)

static unsigned char endianness(void)
{
	uint16_t two_byte = 0x00FF;
	uint8_t low_address = *((uint8_t *)&two_byte);

	if (low_address == 0)
		return ELFDATA2MSB;
	else
		return ELFDATA2LSB;
}

struct sym {
	char *name;
	unsigned long address;
	unsigned long offset;
	void *content;
	int size;
};

static unsigned long get_offset_from_address(Elf *elf, unsigned long addr)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	unsigned long start, end, offset;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		gelf_getshdr(scn, &shdr);
		start = shdr.sh_addr;
		end = start + shdr.sh_size;
		offset = shdr.sh_offset;
		if (addr >= start && addr <= end)
			return addr - start + offset;
	}
	return 0;
}


#define LINE_SIZE 100

static void get_symbol_from_map(Elf *elf, void *base, FILE *f, char *name,
				struct sym *s)
{
	char l[LINE_SIZE];
	char *w, *p, *n;

	s->size = 0;
	s->address = 0;
	s->offset = 0;
	if (fseek(f, 0, SEEK_SET) != 0) {
		perror("File seek failed");
		exit(EXIT_FAILURE);
	}
	while (fgets(l, LINE_SIZE, f)) {
		p = strchr(l, '\n');
		if (!p) {
			err("Missing line ending.\n");
			return;
		}
		n = strstr(l, name);
		if (n)
			break;
	}
	if (!n) {
		err("Unable to find symbol: %s\n", name);
		return;
	}
	w = strchr(l, ' ');
	if (!w)
		return;

	*w = '\0';
	s->address = strtoul(l, NULL, 16);
	if (s->address == 0)
		return;
	s->offset = get_offset_from_address(elf, s->address);
	s->name = name;
	s->content = (void *)base + s->offset;
}

static void get_symbol_from_table(Elf *elf, Elf_Scn *symtab, void *base,
				  char *name, struct sym *s)
{
	GElf_Shdr shdr;
	Elf_Data *data;
	int count;
	int i;
	GElf_Sym sym;
	char *symname;
	int found = 0;
	size_t secndx;
	Elf_Scn *sec;

	gelf_getshdr(symtab, &shdr);
	data = elf_getdata(symtab, NULL);
	count = shdr.sh_size / shdr.sh_entsize;

	for (i = 0; i < count; i++) {
		gelf_getsym(data, i, &sym);
		symname = elf_strptr(elf, shdr.sh_link, sym.st_name);
		if (strcmp(symname, name) == 0) {
			found = 1;
			break;
		}
	}

	s->size = 0;
	s->address = 0;
	s->offset = 0;
	if (!found)
		return;
	secndx = sym.st_shndx;
	if (!secndx)
		return;
	sec = elf_getscn(elf, secndx);
	gelf_getshdr(sec, &shdr);
	s->size = sym.st_size;
	s->address = sym.st_value;
	s->offset = s->address - shdr.sh_addr
			       + shdr.sh_offset;
	s->name = name;
	s->content = base + s->offset;
}

static Elf_Scn *get_symbol_table(Elf *elf)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		gelf_getshdr(scn, &shdr);
		if (shdr.sh_type == SHT_SYMTAB)
			return scn;
	}
	return NULL;
}

static void *map_file(char *file_name, int *size)
{
	struct stat st;
	void *map;
	int fd;

	fd = open(file_name, O_RDWR);
	if (fd < 0) {
		perror(file_name);
		return NULL;
	}
	if (fstat(fd, &st)) {
		perror("Could not determine file size");
		close(fd);
		return NULL;
	}
	*size = st.st_size;
	map = mmap(NULL, *size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		perror("Mapping to memory failed");
		close(fd);
		return NULL;
	}
	close(fd);
	return map;
}

static char *read_file(char *file_name, int *size)
{
	struct stat st;
	char *buf;
	int fd;

	fd = open(file_name, O_RDONLY);
	if (fd < 0) {
		perror(file_name);
		return NULL;
	}
	if (fstat(fd, &st)) {
		perror("Could not determine file size");
		close(fd);
		return NULL;
	}
	*size = st.st_size;
	buf = malloc(*size);
	if (!buf) {
		perror("Allocating memory failed");
		close(fd);
		return NULL;
	}
	if (read(fd, buf, *size) != *size) {
		perror("File read failed");
		close(fd);
		return NULL;
	}
	close(fd);
	return buf;
}

static void print_sym(struct sym *s)
{
	info("sym:    %s\n", s->name);
	info("addr:   0x%lx\n", s->address);
	info("size:   %d\n", s->size);
	info("offset: 0x%lx\n", (unsigned long)s->offset);
}

static void print_usage(char *e)
{
	printf("Usage %s [-s <System.map>] -b <vmlinux> -c <certfile>\n", e);
}

int main(int argc, char **argv)
{
	char *system_map_file = NULL;
	char *vmlinux_file = NULL;
	char *cert_file = NULL;
	int vmlinux_size;
	int cert_size;
	char *vmlinux;
	char *cert;
	FILE *system_map;
	int *used;
	int opt;
	struct sym cert_sym, lsize_sym, used_sym;
	Elf *elf;
	GElf_Ehdr hdr_s, *hdr;
	Elf_Scn *symtab = NULL;

	while ((opt = getopt(argc, argv, "b:c:s:")) != -1) {
		switch (opt) {
		case 's':
			system_map_file = optarg;
			break;
		case 'b':
			vmlinux_file = optarg;
			break;
		case 'c':
			cert_file = optarg;
			break;
		default:
			break;
		}
	}

	if (!vmlinux_file || !cert_file) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	cert = read_file(cert_file, &cert_size);
	if (!cert)
		exit(EXIT_FAILURE);

	vmlinux = map_file(vmlinux_file, &vmlinux_size);
	if (!vmlinux)
		exit(EXIT_FAILURE);

	if (elf_version(EV_CURRENT) == EV_NONE) {
		err("Init libelf failed.\n");
		exit(EXIT_FAILURE);
	}

	elf = elf_memory(vmlinux, vmlinux_size);
	if (!elf) {
		err("Unable to read Elf: %s\n", elf_errmsg(elf_errno()));
		exit(EXIT_FAILURE);
	}

	hdr = gelf_getehdr(elf, &hdr_s);
	if (!hdr) {
		err("Unable to read Elf_hdr: %s\n", elf_errmsg(elf_errno()));
		exit(EXIT_FAILURE);
	}

	if ((hdr->e_ident[EI_MAG0] != ELFMAG0) ||
	    (hdr->e_ident[EI_MAG1] != ELFMAG1) ||
	    (hdr->e_ident[EI_MAG2] != ELFMAG2) ||
	    (hdr->e_ident[EI_MAG3] != ELFMAG3)) {
		err("Invalid ELF magic.\n");
		exit(EXIT_FAILURE);
	}

	if (hdr->e_ident[EI_DATA] != endianness()) {
		err("ELF endian mismatch.\n");
		exit(EXIT_FAILURE);
	}

	if (hdr->e_shoff > vmlinux_size) {
		err("Could not find section header.\n");
		exit(EXIT_FAILURE);
	}

	symtab = get_symbol_table(elf);
	if (!symtab) {
		warn("Could not find the symbol table.\n");
		if (!system_map_file) {
			err("Please provide a System.map file.\n");
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}

		system_map = fopen(system_map_file, "r");
		if (!system_map) {
			perror(system_map_file);
			exit(EXIT_FAILURE);
		}
		get_symbol_from_map(elf, vmlinux, system_map,
				    CERT_SYM, &cert_sym);
		get_symbol_from_map(elf, vmlinux, system_map,
				    USED_SYM, &used_sym);
		get_symbol_from_map(elf, vmlinux, system_map,
				    LSIZE_SYM, &lsize_sym);
		cert_sym.size = used_sym.address - cert_sym.address;
	} else {
		info("Symbol table found.\n");
		if (system_map_file)
			warn("System.map is ignored.\n");
		get_symbol_from_table(elf, symtab, vmlinux,
				      CERT_SYM, &cert_sym);
		get_symbol_from_table(elf, symtab, vmlinux,
				      USED_SYM, &used_sym);
		get_symbol_from_table(elf, symtab, vmlinux,
				      LSIZE_SYM, &lsize_sym);
	}

	if (!cert_sym.offset || !lsize_sym.offset || !used_sym.offset)
		exit(EXIT_FAILURE);

	print_sym(&cert_sym);
	print_sym(&used_sym);
	print_sym(&lsize_sym);

	used = (int *)used_sym.content;

	if (cert_sym.size < cert_size) {
		err("Certificate is larger than the reserved area!\n");
		exit(EXIT_FAILURE);
	}

	/* If the existing cert is the same, don't overwrite */
	if (cert_size == *used &&
	    strncmp(cert_sym.content, cert, cert_size) == 0) {
		warn("Certificate was already inserted.\n");
		exit(EXIT_SUCCESS);
	}

	if (*used > 0)
		warn("Replacing previously inserted certificate.\n");

	memcpy(cert_sym.content, cert, cert_size);
	if (cert_size < cert_sym.size)
		memset(cert_sym.content + cert_size,
			0, cert_sym.size - cert_size);

	if (hdr->e_ident[EI_CLASS] == ELFCLASS64) {
		u64 *lsize;

		lsize = (u64 *)lsize_sym.content;
		*lsize = *lsize + cert_size - *used;
	} else {
		u32 *lsize;

		lsize = (u32 *)lsize_sym.content;
		*lsize = *lsize + cert_size - *used;
	}
	*used = cert_size;
	info("Inserted the contents of %s into %lx.\n", cert_file,
						cert_sym.address);
	info("Used %d bytes out of %d bytes reserved.\n", *used,
						 cert_sym.size);
	if (munmap(vmlinux, vmlinux_size) == -1) {
		perror(vmlinux_file);
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
