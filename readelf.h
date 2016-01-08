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

#endif /*__READELF_H_ */

