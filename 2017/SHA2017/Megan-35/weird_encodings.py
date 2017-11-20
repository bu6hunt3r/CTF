import base64
import sys

pt = sys.argv[1]
type_encoding = sys.argv[2]

atom128 = "/128GhIoPQROSTeUbADfgHijKLM+n0pFWXY456xyzB7=39VaqrstJklmNuZvwcdEC"
megan35 = "3GHIJKLMNOPQRSTUb=cdefghijklmnopWXYZ/12+406789VaqrstuvwxyzABCDEF5"
zong22 = "ZKj9n+yf0wDVX1s/5YbdxSo=ILaUpPBCHg8uvNO4klm6iJGhQ7eFrWczAMEq3RTt2"
hazz15 = "HNO4klm6ij9n+J2hyf0gzA8uvwDEq3X1Q7ZKeFrWcVTts/MRGYbdxSo=ILaUpPBC5"
b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
 
class B64weird_encodings:
 
    def __init__(self, translation):
        b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        self.srch = dict(zip(b, translation))
        self.revlsrch = dict(zip(translation, b))
 
    def encode(self, pt):
        global srch
        b64 = base64.b64encode(pt)
        r = "".join([self.srch[x] for x in b64])
        return r
 
    def decode(self, code):
        global revlsrch
        b64 = "".join([self.revlsrch[x] for x in code])
        r = base64.b64decode(b64)
        return r    
 
def encode(variant, pt):
    encoder = B64weird_encodings(variant)
    return encoder.encode(pt)
 
def decode(variant, code):
    try:
        encoder = B64weird_encodings(variant)
        return encoder.decode(code)
    except KeyError:
        return "Not valid"
    except TypeError:
        return "Padding iccorrect"
 

 
if type_encoding == 'enc':
    print 'base64: ', encode(b, pt)
    print 'atom128: ', encode(atom128, pt)
    print 'megan35: ', encode(megan35, pt)
    print 'hazz15: ', encode(hazz15, pt)
    print 'zong22: ', encode(zong22, pt)    
elif type_encoding == 'dec':
    print 'base64: ', decode(b, pt)
    print 'atom128: ', decode(atom128, pt)
    print 'megan35: ', decode(megan35, pt)
    print 'hazz15: ' , decode(hazz15, pt)
    print 'zong22: ', decode(zong22, pt)
else:
    print "no valid type of encoding"