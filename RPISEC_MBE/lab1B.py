from __future__ import print_function
from z3 import *
from pwn import *

hard_wired1 = 0x1337d00d
hard_wired2 = b"Q}|u`sfg~sf{}|a3"
hard_wired3 = b"Congratulations_"

print("Original: {}".format(hard_wired1))

def crack():
    log.info("Adding conditions...")
    solver=Solver()
    s = BitVec("s",8*4)
    solver.add(s - hard_wired1 <= 0x15)
    
    for i in range(15):
       #print ord(hard_wired2[i]) 
       solver.add(s ^ BitVecVal(ord(hard_wired2[i]),8*4) == BitVecVal(ord(hard_wired3[i]),8*4))

    if solver.check() == sat:
        log.success("Conditions are \033[4;31m{}\033[0m".format(solver.check()))
        m=solver.model()
        solution=m.evaluate(s).as_long()
        log.info(">>> Solution should be: \033[4;32m{}\033[0m".format(0x1337d00d-solution))
    return (0x1337d00d-solution)

def check():
    r=ssh(user="lab1B",password="n0_str1ngs_n0_pr0bl3m", host="192.168.13.101")
    p=r.process(["/levels/lab01/lab1B"])
    print(p.recvlines(3))
    sol=str(crack())
    p.sendline(sol)
    p.recv(4096)
    r.interactive()

check()
