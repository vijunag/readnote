/*
 * Author: Vijay Nag
 * Date: 06/01/2015
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <elf.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

/* may be defined in BSD kernel */
#ifndef IS_ELF
#define IS_ELF(ehdr)  ((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
       (ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
       (ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
       (ehdr).e_ident[EI_MAG3] == ELFMAG3)
#endif /*IS_ELF*/

#define SYSCALL_EXIT_ON_ERR(syscall)                          \
({                                                            \
 int ret = syscall;                                           \
 if (ret < 0) {                                               \
   fprintf(stderr, "%s error at %s:%d, errno(%d) = %s\n",     \
			#syscall, __func__, __LINE__,errno, strerror(errno));   \
    exit(ret);                                                \
 }                                                            \
 ret;                                                         \
 })

#define LOGERR_EXIT(msg) \
do {                     \
	fprintf(stderr, msg);  \
  exit(-1);              \
} while(0);

#define LOG_MSG(msg) \
	fprintf(stderr, msg);

typedef struct Elf_ctxt {
	union {
	 Elf32_Ehdr elf32_ehdr;
	 Elf64_Ehdr elf64_ehdr;
	 unsigned char e_ident[EI_NIDENT];
	} elf_ehdr;
#define elf32_ehdr elf_ehdr.elf32_ehdr
#define elf64_ehdr elf_ehdr.elf64_ehdr
#define e_ident    elf_ehdr.e_ident

	void *mmap_addr;
	uint8_t is32; /* is it 32 bit elf ? */
} Elf_ctxt;

int elf_read_note_section(Elf_ctxt *elf, prstatus_t *prs,
		                      prpsinfo_t *pri)
{
}

int main()
{
	Elf_ctxt elf = {0};
	const char *filename = "core";
	struct stat st;
	prstatus_t prs = {0};
	prpsinfo_t pri = {0};

	printf("sizeof(Elf32_Ehdr) = %d, sizeof(Elf64_Ehdr) = %d\n",
			sizeof(elf.elf32_ehdr), sizeof(elf.elf64_ehdr));

	/* open the core file */
	int fd = SYSCALL_EXIT_ON_ERR(open(filename, O_RDONLY));

	SYSCALL_EXIT_ON_ERR(fstat(fd, &st));

	/* read the elf header from the core
	 * and mmap it only if it is an elf
	 */
	size_t sz = SYSCALL_EXIT_ON_ERR(read(fd, &elf, sizeof(elf.elf_ehdr)));
	if (sizeof(elf.elf_ehdr) != sz) {
		LOGERR_EXIT("Cannot read the elf header\n");
	}
	if (!IS_ELF(elf)) {
		LOGERR_EXIT("Not an ELF\n");
  }

	if (elf.e_ident[EI_CLASS] == ELFCLASS32) {
		LOG_MSG("Elf type: ELF 32-bit LSB executable, Intel 80386\n");
		elf.is32 = 1;
	} else if (elf.e_ident[EI_CLASS] == ELFCLASS64) {
		LOG_MSG("Elf type: ELF 64-bit LSB core file x86-64\n");
	} else {
		LOGERR_EXIT("Invalid elf type\n");
	}

	elf.mmap_addr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (elf.mmap_addr < 0) {
		LOGERR_EXIT("File mapping error\n");
	}

	elf_read_note_section(&elf, &prs, &pri);
	return 0;
}

