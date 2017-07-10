from z3 import *

P = 0x10000000000000000000000000000000000000000000000000000000000000425L

def get_result_from_z3(result):
    dic = {}
    for d in result.decls():
        dic[d.name().lstrip('S')] = result[d].as_long()
    return dic

def str2num(s):
    return int(s.encode('hex'), 16)


def process(m):
    tmp = m
    res = 0
    for i in bin(tmp)[2:]:
        res = res << 1;
        if (int(i)):
            res = res ^ tmp
        if (res >> 256):
            res = res ^ P
    return res
    
def main():
    x = [BitVec('x_%s' % i, 1) for i in range(256)]

    ct0=0x496138892d6fc3b4788e417942264acb2d5b3ad80fb82af6b637b8201e868348
    ct1=0x389d1cded6281407357d4a3b5a4c382c883d556fe743914a66fce7346c949365
    ct2=0x7ff85ba3640436fc5dcf51f446009fdad06823634eed009e1502165ee7355e55

    fake_secret1 = "I_am_not_a_secret_so_you_know_me"
    fake_secret2 = "feeddeadbeefcafefeeddeadbeefcafe"

    k1 = ct1 ^ str2num(fake_secret1)
    k2 = ct2 ^ str2num(fake_secret2)

    p_k0 = k2 ^ k1 ^ process(k1)

    s = Solver()
    temp =[]

    for i in range(256):
        l = ZeroExt(511,x[i]) * BitVecVal(process( 2**i ), 512)
        # Because P is 256 bits, so I use extend to make BitVec multiply possible
        # Use BitVecVal so the value will be consider, otherwise z3 sees it as zero
        temp.append( l )

    # xor together

    a = temp[0]
    for i in temp[1:]:
        a = a^i


    s.add(a == p_k0)

    if s.check() == sat:

        res = get_result_from_z3( s.model() )

        t = ''
        for i in range(256):
            t += str(eval("res['x_{}']".format(i)))
        print t[::-1]

        bla = int(t[::-1], 2) ^ ct0
        print hex(bla)[2:-1].decode('hex')



    else:
        print 'UNSAT'

if __name__=="__main__":
    main()