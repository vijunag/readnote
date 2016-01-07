#include <sys/param.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/procfs.h>
#include <sys/queue.h>
#include <elf.h>
//#include <machine/vmparam.h>

#include <err.h>
#include <fcntl.h>
#include <link.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__sparc64__)
#include <machine/frame.h>
#define REG_PC(r) ((r)->r_pc)
#define REG_SP(r) ((r)->r_out[6] + SPOFF)
#define FRAME_PC(fr)  ((fr)->fr_pc)
#define FRAME_NEXT(fr)  ((fr)->fr_fp + SPOFF)
#elif defined(__i386__)
struct frame {
  uint32_t fr_ebp;
  uint32_t fr_eip;
};
#define REG_PC(r) ((r)->r_eip)
#define REG_SP(r) ((r)->r_ebp)
#define FRAME_PC(fr)  ((fr)->fr_eip)
#define FRAME_NEXT(fr)  ((fr)->fr_ebp)
#else
#define REG_PC(r) ((r)->r_rip)
#define REG_SP(r) ((r)->r_rbp)
#define FRAME_PC(fr)  ((fr)->r_rip)
#define FRAME_NEXT(fr)  ((fr)->r_rbp)
#endif

#define max(a, b) ((a) > (b) ? (a) : (b))

static void elf_decode_note(Elf_Ehdr *ce, struct prstatus **prsp,
    struct prpsinfo **prip);
static Elf_Phdr *elf_find_phdr_by_address(Elf_Ehdr *e, Elf_Addr addr, int idx);
static Elf_Phdr *elf_find_phdr_by_type(Elf_Ehdr *e, int type, int idx);
static Elf_Shdr *elf_find_shdr(Elf_Ehdr *e, char *name, int idx);
static Elf_Sym *elf_find_sym_by_address(Elf_Ehdr *e, Elf_Addr addr);
static Elf_Sym *elf_find_sym_by_name(Elf_Ehdr *e, char *name);
static int elf_get_linkmap(char *name, Elf_Ehdr *ce, Elf_Ehdr **ae,
    struct link_map **al);
static Elf_Ehdr *elf_map_file(char *name, off_t *sz);
static int elf_search_symbol(Elf_Addr addr, Elf_Ehdr **ae,
    struct link_map **al, int n, Elf_Addr *value, char **name);
static void *elf_translate_core_address(Elf_Ehdr *e, Elf_Addr addr);

static void usage(void);

int
main(int ac, char **av)
{
  struct prstatus *prs;
  struct prpsinfo *pri;
  struct link_map **al;
  struct frame *fr;
  Elf_Addr value;
  Elf_Ehdr **ae;
  Elf_Ehdr *ce;
  Elf_Addr pc;
  Elf_Addr sp;
  Elf_Addr fp;
  char *exec;
  char *core;
  char *name;
  int ch;
  int n;

  exec = "a.out";
  core = "a.out.core";
  while ((ch = getopt(ac, av, "c:e:")) != -1)
    switch (ch) {
    case 'c':
      core = optarg;
      break;
    case 'e':
      exec = optarg;
      break;
    default:
      usage();
    }
  ac -= optind;
  av += optind;
  if (ac != 0)
    usage();
  ce = elf_map_file(core, NULL);
  if (ce->e_type != ET_CORE)
    errx(1, "not a core file");
#if 0
  n = elf_get_linkmap(exec, ce, NULL, NULL);
  if ((ae = malloc(n * sizeof(*ae))) == NULL ||
      (al = malloc(n * sizeof(*al))) == NULL)
    err(1, NULL);
  elf_get_linkmap(exec, ce, ae, al);
#endif

  elf_decode_note(ce, &prs, &pri);
  pc = REG_PC(&prs->pr_reg);
  sp = REG_SP(&prs->pr_reg);

  printf("osreldate: %d\n", prs->pr_osreldate);
  printf("cursig: %d\n", prs->pr_cursig);
  printf("pid: %d\n", prs->pr_pid);
  printf("fname: %s\n", pri->pr_fname);
  printf("args: %s\n", pri->pr_psargs);
  printf("pc: %#lx\n", pc);
  printf("sp: %#lx\n", sp);

  printf("stack trace:\n");
  /*
  for (fp = sp; (fr = elf_translate_core_address(ce, fp)) != NULL;
      fp = FRAME_NEXT(fr), pc = FRAME_PC(fr)) {
    elf_search_symbol(pc, ae, al, n, &value, &name);
    printf("%s() at %s+%#lx\n", name, name, pc - value);
  }
  */
  return (0);
}

static void
elf_decode_note(Elf_Ehdr *ce, struct prstatus **prsp, struct prpsinfo **prip)
{
  struct prstatus *prs;
  struct prpsinfo *pri;
  Elf_Phdr *p;
  Elf_Note *n;
  char *v;

  if ((p = elf_find_phdr_by_type(ce, PT_NOTE, 0)) == NULL)
    errx(1, "can't find note header");
  for (v = (char *)ce + p->p_offset;
       v < (char *)ce + p->p_offset + p->p_filesz;
       v += sizeof(*n) + n->n_namesz + n->n_descsz) {
    n = (Elf_Note *)v;
    switch (n->n_type) {
    case NT_PRSTATUS:
      prs = (struct prstatus *)(v + sizeof(*n) +
          n->n_namesz);
      if (prs->pr_version != PRSTATUS_VERSION ||
          prs->pr_statussz != sizeof(*prs) ||
          prs->pr_gregsetsz != sizeof(struct reg) ||
          prs->pr_fpregsetsz != sizeof(struct fpreg))
        errx(1, "prstatus size or version mismatch");
      *prsp = prs;
      break;
    case NT_FPREGSET:
      break;
    case NT_PRPSINFO:
      pri = (struct prpsinfo *)(v + sizeof(*n) +
          n->n_namesz);
      if (pri->pr_version != PRPSINFO_VERSION ||
          pri->pr_psinfosz != sizeof(*pri))
        errx(1, "prpsinfo size or version mismatch");
      *prip = pri;
      break;
    default:
      break;
    }
  }
}

static Elf_Phdr *
elf_find_phdr_by_address(Elf_Ehdr *e, Elf_Addr addr, int idx)
{
  Elf_Phdr *p;
  int i;

  if (e->e_type != ET_CORE)
    errx(1, "not a core header");
  p = (Elf_Phdr *)((char *)e + e->e_phoff);
  for (i = idx; i < e->e_phnum; i++) {
    if (addr >= p[i].p_vaddr &&
        addr < p[i].p_vaddr + p[i].p_filesz)
      return (&p[i]);
  }
  return (NULL);
}

static Elf_Phdr *
elf_find_phdr_by_type(Elf_Ehdr *e, int type, int idx)
{
  Elf_Phdr *p;
  int i;

  p = (Elf_Phdr *)((char *)e + e->e_phoff);
  for (i = idx; i < e->e_phnum; i++) {
    if (p[i].p_type == type)
      return (&p[i]);
  }
  return (NULL);
}

static Elf_Shdr *
elf_find_shdr(Elf_Ehdr *e, char *name, int idx)
{
  char *shstrtab;
  Elf_Shdr *sh;
  int i;

  if (e->e_shoff == 0)
    return (NULL);
  sh = (Elf_Shdr *)((char *)e + e->e_shoff);
  shstrtab = (char *)e + sh[e->e_shstrndx].sh_offset;
  for (i = idx; i < e->e_shnum; i++) {
    if (strcmp(name, shstrtab + sh[i].sh_name) == 0)
      return (&sh[i]);
  }
  return (NULL);
}

static Elf_Sym *
elf_find_sym_by_address(Elf_Ehdr *e, Elf_Addr addr)
{
  Elf_Shdr *sh;
  Elf_Sym *st;
  int i;

  if ((sh = elf_find_shdr(e, ".symtab", 0)) == NULL)
    return (NULL);
  st = (Elf_Sym *)((char *)e + sh->sh_offset);
  for (i = 0; i < sh->sh_size / sizeof(*st); i++) {
    if (addr >= st[i].st_value &&
        addr < st[i].st_value + st[i].st_size)
      return (&st[i]);
  }
  return (NULL);
}

static Elf_Sym *
elf_find_sym_by_name(Elf_Ehdr *e, char *name)
{
  Elf_Shdr *sh;
  Elf_Sym *st;
  char *strtab;
  int i;

  if ((sh = elf_find_shdr(e, ".strtab", 0)) == NULL)
    return (NULL);
  strtab = (char *)e + sh->sh_offset;
  if ((sh = elf_find_shdr(e, ".symtab", 0)) == NULL)
    return (NULL);
  st = (Elf_Sym *)((char *)e + sh->sh_offset);
  for (i = 0; i < sh->sh_size / sizeof(*st); i++) {
    if (strcmp(name, strtab + st[i].st_name) == 0)
      return (&st[i]);
  }
  return (NULL);
}

static int
elf_get_linkmap(char *name, Elf_Ehdr *ce, Elf_Ehdr **ae, struct link_map **al)
{
  Elf_Addr data_addr;
  Elf_Addr rtld_addr;
  struct link_map *l;
  struct r_debug *r;
  Elf_Size maxdsiz;
  Elf_Ehdr *ie;
  Elf_Phdr *ip;
  Elf_Ehdr *e;
  Elf_Phdr *p;
  Elf_Sym *st = NULL;
  off_t esz;
  off_t isz;
  int i;
  int n;

  n = 0;
  maxdsiz = MAXDSIZ;
  data_addr = 0;
  e = elf_map_file(name, &esz);
  ip = elf_find_phdr_by_type(e, PT_INTERP, 0);
  if (ip == NULL)
    printf("can't get interp section");
 // ie = elf_map_file((char *)e + (ip ? ip->p_offset : 0), &isz);
  for (i = 0; (p = elf_find_phdr_by_type(e, PT_LOAD, i)) != NULL; i++)
    data_addr = max(data_addr, trunc_page(p->p_vaddr));
  rtld_addr = round_page(data_addr + maxdsiz);
 // st = elf_find_sym_by_name(ie, "r_debug");
  if (st == NULL)
    printf("can't find r_debug in rtld");
  r = (struct r_debug *)elf_translate_core_address(ce,
      rtld_addr + (st ? st->st_value : 0));
  l = elf_translate_core_address(ce, (Elf_Addr)r->r_map);
  for (;;) {
    if (ae != NULL) {
      name = elf_translate_core_address(ce,
          (Elf_Addr)l->l_name);
      ae[n] = elf_map_file(name, NULL);
    }
    if (al != NULL)
      al[n] = l;
    n++;
    if (l->l_next == NULL)
      break;
    l = elf_translate_core_address(ce, (Elf_Addr)l->l_next);
  }
  munmap(e, esz);
  munmap(ie, isz);
  return (n);
}

static Elf_Ehdr *
elf_map_file(char *name, off_t *sz)
{
  struct stat st;
  Elf_Ehdr *e;
  char *v;
  int fd;

  if ((fd = open(name, O_RDONLY)) < 0 ||
      fstat(fd, &st) < 0)
    errx(1, NULL);
  v = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if ((e = (Elf_Ehdr *)v) == MAP_FAILED)
    err(1, NULL);
  if (!IS_ELF(*e))
    errx(1, "not an elf file");
  if (e->e_ident[EI_CLASS] != ELF_CLASS ||
      e->e_ident[EI_DATA] != ELF_DATA ||
      e->e_ident[EI_VERSION] != EV_CURRENT ||
      e->e_ident[EI_OSABI] != ELFOSABI_FREEBSD)
    errx(1, "unsupported elf file");
  if (e->e_machine != ELF_ARCH)
    errx(1, "unsupported architecture");
  if (sz != NULL)
    *sz = st.st_size;
  return (e);
}

static int
elf_search_symbol(Elf_Addr addr, Elf_Ehdr **ae, struct link_map **al, int n,
    Elf_Addr *value, char **name)
{
  struct link_map *l;
  Elf_Addr base;
  Elf_Addr best;
  Elf_Addr diff;
  char *strtab;
  Elf_Shdr *sh;
  Elf_Ehdr *e;
  Elf_Sym *st;
  int i;

  best = 0;
  diff = 0;
  for (i = 0; i < n; i++) {
    diff = addr - (Elf_Addr)al[i]->l_addr;
    if (diff >= 0 && (best == 0 || diff < best)) {
      best = diff;
      e = ae[i];
      l = al[i];
    }
  }
  if (e->e_type != ET_EXEC)
    base = (Elf_Addr)l->l_addr;
  else
    base = 0;
  if ((st = elf_find_sym_by_address(e, addr - base)) != NULL &&
      (sh = elf_find_shdr(e, ".strtab", 0)) != NULL) {
    strtab = (char *)e + sh->sh_offset;
    *name = strtab + st->st_name;
    *value = base + st->st_value;
    return (1);
  }
  *name = NULL;
  *value = 0;
  return (0);
}

static void *
elf_translate_core_address(Elf_Ehdr *e, Elf_Addr addr)
{
  Elf_Phdr *p;

  p = elf_find_phdr_by_address(e, addr, 0);
  if (p == NULL)
    return (NULL);
  return (char *)e + p->p_offset + (addr - p->p_vaddr);
}

static void
usage(void)
{

  fprintf(stderr, "usage: coredump -c prog.core -e prog\n");
  exit(1);
}

