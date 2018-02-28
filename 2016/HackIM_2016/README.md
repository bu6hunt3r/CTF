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

