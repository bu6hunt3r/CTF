# Shellcode generating shellcode
## Advanced shellcoding on x86_64

In my opinion the following description demonstrates quite nicely the possibility to use shellcode as a wrapper for writing another payload (this one we originally would like to execute) into process' memory space.

The challenge described below focusses on shellcoding, so no NX activated this time...

```
$ checksec --file ./sandman 
RELRO           Partial RELRO
STACK CANARY    No canary found  
NX              NX disabled
PIE             No PIE
RPATH           No RPATH
RUNPATH         No RUNPATH
FORTIFY         No
Fortified       0
Fortifiable     2
FILE            ./sandman
```

### Recon

Any syscalls made besides always present mmap/mprotect etc. calls?

```
$ strace ./sandman
pipe([3, 4])                            = 0              
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f644877fa10) = 4756
rt_sigaction(SIGCHLD, {sa_handler=SIG_IGN, sa_mask=[CHLD], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7f6447f99140}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGSEGV, {sa_handler=0x400b7d, sa_mask=[SEGV], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7f6447f99140}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGTRAP, {sa_handler=0x400b7d, sa_mask=[TRAP], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7f6447f99140}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGALRM, {sa_handler=0x400b7d, sa_mask=[ALRM], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7f6447f99140}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
alarm(5)                                = 0              
read(0, 0x7ffc61db119c, 4)              = ? ERESTARTSYS (To be restarted if SA_RESTART is set)                    
--- SIGALRM {si_signo=SIGALRM, si_code=SI_KERNEL} ---    
getpid()                                = 4754           
exit_group(1)                           = ?              

```
Well, here are the intersting facts:
+ The process initializes a pipe with two elements (the first for reading, second for writing, see ```man pipe```).
+ It's cloning it's memory layout into new child process (```clone()``` is like fork, besides the fact, that entire execution context (memory space, fd table, signal handler table) gets transferrde to child.

+ Multiple signal handlers are registered by parent process, such as SIGCHLD which is raised by child when terminating it's execution.
+ 5 seconds time to interact with parent until raising ALARM
+ We're prompted for 4 byte input

There are actually two paths in execution flow (like ```fork()``` also ```clone()``` returns zero in child). One for the parent and the other for its child.

```
400ebc:       call   400a80 <fork@plt>
400ec1:       test   eax,eax
400ec3:       jne    400ef7 <fork@plt+0x477>
400ec5:       call   400990 <getpid@plt>
400eca:       mov    esi,0x400b7d
400ecf:       mov    edi,0xe
400ed4:       call   400a30 <signal@plt>
400ed9:       mov    edi,0x5
400ede:       call   4009e0 <alarm@plt>
400ee3:       mov    eax,DWORD PTR [rbp-0x30]
400ee6:       mov    edi,eax
400ee8:       call   400e2b <fork@plt+0x3ab>
400eed:       mov    edi,0x0
400ef2:       call   400a70 <exit@plt>
400ef7:       mov    esi,0x1
400efc:       mov    edi,0x11
400f01:       call   400a30 <signal@plt>
400f06:       mov    esi,0x400b7d
400f0b:       mov    edi,0xb
400f10:       call   400a30 <signal@plt>
400f15:       mov    esi,0x400b7d
400f1a:       mov    edi,0x5
400f1f:       call   400a30 <signal@plt>
400f24:       mov    esi,0x400b7d
400f29:       mov    edi,0xe
400f2e:       call   400a30 <signal@plt>
400f33:       mov    edi,0x5
400f38:       call   4009e0 <alarm@plt>
400f3d:       mov    DWORD PTR [rbp-0x24],0x0
400f44:       lea    rax,[rbp-0x24]
400f48:       mov    edx,0x4
400f4d:       mov    rsi,rax
400f50:       mov    edi,0x0
400f55:       call   400a00 <read@plt>
```

Our input gets stored in local variable on stack at position ```rbp-0x24```. Afterwards memory page gets allocated via ```mmap()``` with its size provided by input previously:

```
400f69:       mov    r9d,0x0
400f6f:       mov    r8d,0xffffffff
400f75:       mov    ecx,0x22
400f7a:       mov    edx,0x7
400f7f:       mov    rsi,rax
400f82:       mov    edi,0x0

Pseudo:
mmap(addr=0, size=bufSize, prot=0x7, flags=0x22, fd=0xffffffff, offset=0)
```

- If addr is NULL, then the kernel chooses the address at which to create the mapping (See manpage).
- Protections for memory area are read/write/exec.
- Flags are MAP_ANONYMOUS (don't associate a file to memory area) and PROT_WRITE (page can be written).

```
/usr/include/x86_64-linux-gnu/bits/mman-linux.h:58:#  define MAP_ANONYMOUS      0x20 /* don't use a file */
/usr/include/asm-generic/mman-common.h:10:#define PROT_WRITE    0x2             /* page can be written */
```

Afterwards user input gets copied to new allocated memory area via read syscall at 0x00400fd6.
To limit syscalls that can be sent from parent to kernel, the running process initiates various seccomp rules. The following snippet is an excerpt from one of these three procedures:

```
401022:       mov    rax,QWORD PTR [rbp-0x18]
401026:       mov    ecx,0x0
40102b:       mov    edx,0x0
401030:       mov    esi,0x7fff0000
401035:       mov    rdi,rax
401038:       mov    eax,0x0
40103d:       call   400980 <seccomp_rule_add@plt>
```

According to 64-bit calling convention rdx has to contain third argument for function call, which is syscall number not to restrict in running process. Read/write/exit are the possible ones (radare2 asl command).
Going further, our buffer gets called at 0x4010fc. I will call this a jump to "parent shellcode" in future.

```
4010f3:       mov    rdx,QWORD PTR [rbp-0x20]
4010f7:       mov    eax,0x0
4010fc:       call   rdx
```

In between child process waits for input via read syscall at 0x00400ee8 from read file descriptor from pipe created at startup.

In child there are two interesting steps:
- One byte from user input gets copied onto stack

```
400e3f:       lea    rcx,[rbp-0x9]
400e43:       mov    eax,DWORD PTR [rbp-0x14]
400e46:       mov    edx,0x1
400e4b:       mov    rsi,rcx
400e4e:       mov    edi,eax
400e50:       call   400a00 <read@plt>
```

- A call to 0x400ddf with the newly populated local buffer:

```
400e60:       movzx  eax,BYTE PTR [rbp-0x9]
400e64:       movsx  edx,al
400e67:       mov    eax,DWORD PTR [rbp-0x14]
400e6a:       mov    esi,edx
400e6c:       mov    edi,eax
400e6e:       call   400ddf <fork@plt+0x35f>
```





