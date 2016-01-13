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

/* Number of each register in the `gregset_t' array.  */
# define R15	0
# define R14	1
# define R13	2
# define R12	3
# define RBP	4
# define RBX	5
# define R11	6
# define R10	7
# define R9	8
# define R8	9
# define RAX	10
# define RCX	11
# define RDX	12
# define RSI	13
# define RDI	14
# define ORIG_RAX 15
# define RIP	16
# define CS	17
# define EFLAGS	18
# define RSP	19
# define SS	20
# define FS_BASE 21
# define GS_BASE 22
# define DS	23
# define ES	24
# define FS	25
# define GS	26

/* Type for general register.  */
__extension__ typedef long long int greg64_t;
/* Number of general registers.  */
#define NGREG64	27
/* Container for all general registers.  */
typedef greg64_t gregset64_t[NGREG64];

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
	elf_int_sinfo pr_sinfo;
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

typedef struct elf64_prpsinfo {
    char pr_state;      /* Numeric process state.  */
    char pr_sname;      /* Char for pr_state.  */
    char pr_zomb;     /* Zombie.  */
    char pr_nice;     /* Nice val.  */
    char pr_flag[8];      /* Flags.  */
    char gap[4];
    char pr_uid[4];
    char pr_gid[4];
    char pr_pid[4];
    char pr_ppid[4];
    char pr_pgrp[4];
    char pr_sid[4];
    char pr_fname[16];      /* Filename of executable.  */
    char pr_psargs[80];     /* Initial part of arg list.  */
} elf64_prpsinfo_t;
#endif /*__READELF_H_ */

