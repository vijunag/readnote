/*
 * Author: Vijay Nag
 * Date: 06/01/2015
 */

#ifndef __READELF_H_
#define __READELF_H_

#define ALIGN_ADDR(addr, boundary) \
  ((((unsigned long) (addr) + (boundary) - 1) >= (unsigned long) (addr))      \
	    ? (((unsigned long) (addr) + ((boundary) - 1)) & ~ (unsigned long) ((boundary)-1)) \
			   : ~ (unsigned long) 0)

#ifndef IS_ELF
#define IS_ELF(ehdr)  ((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
       (ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
       (ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
       (ehdr).e_ident[EI_MAG3] == ELFMAG3)
#endif /*IS_ELF*/

/* Type for general register.  */
__extension__ typedef long long int greg64_t;
/* Number of general registers.  */
#define NGREG64	27
/* Container for all general registers.  */
typedef greg64_t gregset64_t[NGREG64];
/* Number of each register in the `gregset_t' array.  */
enum
{
  REG_R8 = 0,
# define REG_R8		REG_R8
  REG_R9,
# define REG_R9		REG_R9
  REG_R10,
# define REG_R10	REG_R10
  REG_R11,
# define REG_R11	REG_R11
  REG_R12,
# define REG_R12	REG_R12
  REG_R13,
# define REG_R13	REG_R13
  REG_R14,
# define REG_R14	REG_R14
  REG_R15,
# define REG_R15	REG_R15
  REG_RDI,
# define REG_RDI	REG_RDI
  REG_RSI,
# define REG_RSI	REG_RSI
  REG_RBP,
# define REG_RBP	REG_RBP
  REG_RBX,
# define REG_RBX	REG_RBX
  REG_RDX,
# define REG_RDX	REG_RDX
  REG_RAX,
# define REG_RAX	REG_RAX
  REG_RCX,
# define REG_RCX	REG_RCX
  REG_RSP,
# define REG_RSP	REG_RSP
  REG_RIP,
# define REG_RIP	REG_RIP
  REG_EFL,
# define REG_EFL	REG_EFL
  REG_CSGSFS,		/* Actually short cs, gs, fs, __pad0.  */
# define REG_CSGSFS	REG_CSGSFS
  REG_ERR,
# define REG_ERR	REG_ERR
  REG_TRAPNO,
# define REG_TRAPNO	REG_TRAPNO
  REG_OLDMASK,
# define REG_OLDMASK	REG_OLDMASK
  REG_CR2
# define REG_CR2	REG_CR2
};

typedef int pid_t;
/*
typedef elf64_fpregset_t fpregset64_t;
typedef elf64_fpxregset_t fpxregset64_t;
*/

typedef struct elf_int_sinfo {
	int si_signo;
	int si_code;
	int si_errno;
} elf_int_sinfo;

typedef struct elf64_prstatus {
	elf_int_sinfo pr_info;
	short pr_cursig;
	unsigned long pr_sigpend;
	unsigned long pr_sighold;

	pid_t pr_pid;
	pid_t pr_ppid;
	pid_t pr_pgrp;
	pid_t pr_sid;

	struct timeval pr_utime;
	struct timeval pr_stime;
	struct timeval pr_cutime;
	struct timeval pr_cstime;

  gregset64_t pr_reg;
	int pr_fpvalid;
} elf64_prstatus_t;

#endif /*__READELF_H_ */

