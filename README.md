# readelf

An utility to dissect the NOTE sections in the linux core file.
==================================================================

Example output:
----------------
```
localhost:~/elf]$ ./readelf
Elf type: ELF 64-bit LSB core file x86-64
Program terminated with Signal SIGSEGV, Segmentation fault.
CORE:           NT_PRSTATUS
rax		0x0                   0
rbx		0x0                   0
rcx		0x7f3e99481ff0     139906836340720
rdx		0x7f3e9974b770     139906839263088
rsi		0x400600             4195840
rdi		0x2                   2
rbp		0x7ffd5c123bc0     140726148152256
rsp		0x7ffd5c123bb0     140726148152240
r8		0xb                  11
r9		0x7f3e9974a540     139906839258432
r10		0x1                   1
r11		0x246                 582
r12		0x400480             4195456
r13		0x7ffd5c123ca0     140726148152480
r14		0x0                   0
r15		0x0                   0
rip		0x4005a8             4195752
eflags		0x10246          [ PF ZF IF RF ]
cs		0x33                  51
ss		0x2b                  43
ds		0x0                   0
es		0x0                   0
fs		0x0                   0
gs		0x0                   0

CORE: NT_PRPSINFO
Program Name: main, Args: ./main
State: 0, Nice Value: 0

CORE: NT_SIGINFO
Signal:  SIGSEGV
errno=0, si_code=1, Killer pid=0, si_faulty = (nil)
```
