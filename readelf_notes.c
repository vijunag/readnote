/*
 * Author: Vijay Nag
 * Date: 06/01/2015
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "readelf.h"

/* may be defined in BSD kernel */
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

static void* Elf_find_phdr_by_type(Elf_ctxt *elf, int type, int idx)
{
	 void *res = NULL;
	 int i = 0;
	 int found = 0;
/*
 * Evil macro substition.
 * not meant for anything else.
 */
#define ITER_AND_GET_ELF_PHDR(elf_type, phdr_type, e, _p) \
	  elf_type* _e = (e);\
	 _p = (phdr_type *)((char *)_e + _e->e_phoff); \
	 for (i = idx; i < _e->e_phnum; ++i) { \
		   if (type == _p[i].p_type) { \
				 found = 1; \
		     break; \
			 } \
	 }

	 if (elf->is32) {
		 Elf32_Phdr *p = NULL;
		 ITER_AND_GET_ELF_PHDR(Elf32_Ehdr, Elf32_Phdr, elf->mmap_addr, p);
		 res = found ? p : NULL;
	 } else {
		 Elf64_Phdr *p = NULL;
		 ITER_AND_GET_ELF_PHDR(Elf64_Ehdr, Elf64_Phdr, elf->mmap_addr, p);
		 res = found ? p : NULL;
	 }
	 return res;
#undef ITER_AND_GET_ELF_PHDR
}

static void print_prstatus_info(elf64_prstatus_t *prstatus)
{
	int i = 0;
  struct rorder {
		int idx;
		const char *reg_name;
	};
	static struct rorder reg_print_order[] = { \
		{RAX, "rax"},
		{RBX, "rbx"},
		{RCX, "rcx"},
		{RDX, "rdx"},
		{RSI, "rsi"},
		{RDI, "rdi"},
		{RBP, "rbp"},
		{RSP, "rsp"},
		{R8,  "r8"},
		{R9,  "r9"},
		{R10, "r10"},
		{R11, "r11"},
		{R12, "r12"},
		{R13, "r13"},
		{R14, "r14"},
		{R15, "r15"},
		{RIP, "rip"},
	  {EFLAGS, "eflags"},
		{CS, "cs"},
		{SS, "ss"},
		{DS, "ds"},
		{ES, "es"},
		{FS, "fs"},
		{GS, "gs"},
	 };

	for (i = 0; i < (sizeof(reg_print_order)/sizeof(reg_print_order[0])); ++i) {
		uint64_t idx = reg_print_order[i].idx;
		if (EFLAGS == idx) {
			fprintf(stderr, "%s\t\t0x%x%10s[ PF ZF IF RF ]\n",
					reg_print_order[i].reg_name,
					prstatus->pr_reg[idx], " ");
			continue;
		}
		fprintf(stderr, "%s\t\t0x%llx%20lld\n",
				reg_print_order[i].reg_name,
				prstatus->pr_reg[idx], prstatus->pr_reg[idx]);
	}
}

int elf_read_note_section(Elf_ctxt *elf)
{
	 char *v = NULL;
	 void *phdr = Elf_find_phdr_by_type(elf, PT_NOTE, 0);

/* haha, iterator for note section ;) */
#define HIT_THE_RIGHT_NOTE() \
	 for (v = (char *)elf->mmap_addr + p->p_offset; \
			  v < (char *)elf->mmap_addr + p->p_offset + p->p_filesz;)

	 if (elf->is32) {
		 Elf32_Phdr *p = (Elf32_Phdr*) phdr;
		 Elf32_Nhdr *n = NULL;
		 HIT_THE_RIGHT_NOTE() {
			 n = (Elf32_Nhdr *)v;
		 }
	 } else {
		 Elf64_Phdr *p = (Elf64_Phdr*) phdr;
		 Elf64_Nhdr *n = NULL;
		 char *name = NULL;
		 HIT_THE_RIGHT_NOTE() {
			 n = (Elf64_Nhdr *)v;
			 v += sizeof(*n); /*get the name data*/
			 name = v;
			 v += ALIGN_ADDR(n->n_namesz, 4);
			 switch(n->n_type) {
			  case NT_PRSTATUS: {
					elf64_prstatus_t *prstatus = (elf64_prstatus_t *)v;
					fprintf(stderr, "%s:%10s NT_PRSTATUS\n", name, " ");
					print_prstatus_info(prstatus);
					break;
				}
			  case NT_PRPSINFO: {
					fprintf(stderr, "%s: NT_PRPSINFO\n", name);
					break;
				}
			  case NT_SIGINFO: {
					fprintf(stderr, "%s: NT_SIGINFO\n", name);
					break;
				}
				case NT_FILE: {
					fprintf(stderr, "%s: NT_FILE\n", name);
					break;
				}
				case NT_FPREGSET: {
					fprintf(stderr, "Note(%s): NT_FPREGSET found\n", name);
					break;
				}
				case NT_AUXV: {
					fprintf(stderr, "Note(%s): NT_AUXV found\n", name);
					break;
				}
			  default: {
				  fprintf(stderr, "Note: unknown found with type = 0x%x\n", n->n_type);
					break;
				}
			 }
			 v += ALIGN_ADDR(n->n_descsz, 4);
		 }
	 }
}

int main()
{
	Elf_ctxt elf = {0};
	const char *filename = "test/core";
	struct stat st;

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

	elf_read_note_section(&elf);
	return 0;
}

