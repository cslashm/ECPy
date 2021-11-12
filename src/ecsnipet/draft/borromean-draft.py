# Copyright 2016 Cedric Mesnil <cedric.mesnil@ubinity.com>, Ubinity SAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#python 2 compatibility
from builtins import int,pow

import hashlib
import random
import binascii

from ecpy.curves     import Curve,Point
from ecpy.keys       import ECPublicKey, ECPrivateKey
from ecpy.formatters import decode_sig, encode_sig, list_formats
from ecpy            import ecrand
from ecpy.curves     import ECPyException



# m: bytes     message
# e: bytes     point
# i: int       ring index
# j: int       secret index
def borromean_hash(m,e,i,j):
    enter("borromean_hash")
    i = i.to_bytes(4,'big')
    j = j.to_bytes(4,'big')
    tell("m: %s" % h(m))
    tell("e: %s" % h(e))
    tell("i: %s" % h(i))
    tell("j: %s" % h(j))

    sha256 = hashlib.sha256()
    sha256.update(e)
    sha256.update(m)
    sha256.update(i)
    sha256.update(j)
    d = sha256.digest()
    tell("d: %s" % h(d))
    leave("borromean_hash")
    return d


def point_to_bytes(point, compressed = True):
    if compressed:
        b = point.x.to_bytes(32,'big')
        if point.y & 1 == 1:
            b = b"\x03"+b
        else:
            b = b"\x02"+b
    else:
        b = b"\x04"+point.x.to_bytes(32,'big')+point.y.to_bytes(32,'big')
    return b

def borromean_verify(pubkeys,rings_size,ring_count,
                     msg,sig):
    tell("*** BORROMEAN VERIFY ***")
    curve = Curve.get_curve('secp256k1')
    G     = curve.generator
    order = curve.order

    e0 = sig[0]
    s = sig[1]
    sha256_e0 = hashlib.sha256()
    r0 = 0
    for i in range (0,ring_count):
        tell("\nstep2-3 / ring %d"%i)
        e_ij = borromean_hash(m,e0,i,0)
        for j in range(0,rings_size[i]):
            tell("\n  step2-3 / ring %d / sec %d"%(i,j))
            e_ij = int.from_bytes(e_ij,'big')
            s_ij = int.from_bytes(s[r0+j],'big')
            tell("  index    : %d"%(r0+j))
            tell("  pubkeys[]: %s"%pubkeys[r0+j])
            tell("  s[]      : %x"%s_ij)
            tell("  e_ij     : %x"%e_ij)
            sG_eP = s_ij*G + e_ij*pubkeys[r0+j].W
            tell("  sG_eP :\n  %s"% sG_eP)
            e_ij = point_to_bytes(sG_eP)
            if j != rings_size[i]-1:
                e_ij = borromean_hash(m,e_ij,i,j+1)
            else:
                tell("  e_ij0     : %s"%h(e_ij))
                sha256_e0.update(e_ij)
        r0 += rings_size[i]
    sha256_e0.update(m)
    e0x = sha256_e0.digest()
    return e0 == e0x

def borromean_sign(pubkeys, privkeys,
                   rings_size,private_keys_index,ring_count,
                   msg):
    tell("*** BORROMEAN SIGN ***\n")
    enter("borromean_sign")
    curve = Curve.get_curve('secp256k1')
    G     = curve.generator
    order = curve.order

    e0=None
    s = []
    k = []
    #just declare
    for i in range (0,ring_count):
        k.append(None)
        for j in range (0,rings_size[i]):
            s.append(None)

    #step2-3
    shuffle = random.randint

    r0 = 0
    sha256_e0 = hashlib.sha256()
    for i in range (0,ring_count):
        tell("\nstep2-3 / ring %d"%i)
        k[i] = rrand(i)
        tell("ki : %x"%k[i])
        kiG = k[i]*G
        tell("ki.G :\n  %s"%kiG)
        j0 = private_keys_index[i]
        e_ij = point_to_bytes(kiG)
        tell("e_ij : %s"%h(e_ij))
        for j in range(j0+1, rings_size[i]):
            tell("\n  step2-3 / ring %d / sec %d"%(i,j))
            s[r0+j] = prand(r0+j)
            e_ij = borromean_hash(m,e_ij,i,j)
            e_ij = int.from_bytes(e_ij,'big')
            tell("  index    : %d"%(r0+j))
            tell("  pubkeys[]: %s"%pubkeys[r0+j])
            tell("  s[]      : %x"%s[r0+j])
            tell("  e_ij     : %x"%e_ij)
            sG_eP = s[r0+j]*G + e_ij*pubkeys[r0+j].W
            tell("  sG_eP :\n  %s"% sG_eP)
            e_ij = point_to_bytes(sG_eP)
        tell("\ne0ij :\n  %s"% h(e_ij))
        sha256_e0.update(e_ij)
        r0 += rings_size[i]
    sha256_e0.update(m)
    e0 =  sha256_e0.digest()
    tell("\ne0: %s"%h(e0))
    #step 4
    tell("")
    r0 = 0
    for i in range (0, ring_count):
        tell("\nstep 4 / ring %d"%i)
        j0 = private_keys_index[i]
        e_ij =  borromean_hash(m,e0,i,0)
        e_ij = int.from_bytes(e_ij,'big')
        for j in range(0, j0):
            tell("\n  step 4 / ring %d / sec %d"%(i,j))
            s[r0+j] = prand(r0+j)
            tell("  index    : %d"%(r0+j))
            tell("  pubkeys[]: %s"%pubkeys[r0+j])
            tell("  s[]      : %x"%s[r0+j])
            tell("  e_ij     : %x"%e_ij)
            sG_eP = s[r0+j]*G + e_ij*pubkeys[r0+j].W
            tell("  sG_eP :\n  %s"% sG_eP)
            e_ij = borromean_hash(m,point_to_bytes(sG_eP),i,j+1)
            e_ij = int.from_bytes(e_ij,'big')
        tell("ki   : %x"%k[i])
        tell("xi   : %x"%privkeys[i].d)
        tell("eij* : %x"%e_ij)
        s[r0+j0] = (k[i]-privkeys[i].d*e_ij)%order
        tell("sij* : %x"%s[r0+j0])
        r0 += rings_size[i]

    leave("borromean_sign")
    s = [sij.to_bytes(32,'big')  for sij in s]
    return (e0,s)



def prand(v) :
    r = 0
    for i in range(1,33):
        r = r<<8|(0xa0+v)
    return r

def rrand(v) :
    r = 0
    for i in range(1,33):
        r = r<<8|(0x40+v)
    return r

def h(b):
    return binascii.hexlify(b)

tab=""
trace = True
def tell(m):
    global trace
    if trace:
        print("%s%s"%(tab,m))

def enter(f):
    global tab, trace
    if trace:
        print("%sEntering: %s"%(tab,f))
        tab  = tab + "  "

def leave(f):
    global tab, trace
    if trace:
        tab = tab[0:len(tab)-2]
        print("%sLeaving: %s"%(tab,f))


def strsig(sigma):
    print("e0: %s"%h(sigma[0]))
    i=0
    for s in sigma[1]:
        print("s%d: %s"%(i,h(s)))
        i += 1

if __name__ == "__main__":

    #
    # layout:
    # nrings = 2
    #   ring 1 has 2 keys
    #   ring 2 has 3 keys
    #
    # pubs=[ring1-key1, ring1-key2,
    #       ring2-key1, ring2-key2, ring2-key3]
    #
    # k = [ring1-rand, ring2-rand]
    # sec = [ring1-sec2, ring2-sec1]
    # rsizes = [2,3]
    # secidx = [1,0]
    #
    #

    cv     = Curve.get_curve('secp256k1')

    seckey0  = ECPrivateKey(0xf026a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5, cv)
    seckey1  = ECPrivateKey(0xf126a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5, cv)
    seckey2  = ECPrivateKey(0xf226a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5, cv)
    seckey3  = ECPrivateKey(0xf326a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5, cv)
    seckey4  = ECPrivateKey(0xf426a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5, cv)
    seckey5  = ECPrivateKey(0xf526a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5, cv)
    seckey6  = ECPrivateKey(0xf626a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5, cv)
    seckey7  = ECPrivateKey(0xf726a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5, cv)
    seckey8  = ECPrivateKey(0xf826a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5, cv)

    pubkey0 = seckey0.get_public_key()
    pubkey1 = seckey1.get_public_key()
    pubkey2 = seckey2.get_public_key()
    pubkey3 = seckey3.get_public_key()
    pubkey4 = seckey4.get_public_key()
    pubkey5 = seckey5.get_public_key()
    pubkey6 = seckey6.get_public_key()
    pubkey7 = seckey7.get_public_key()
    pubkey8 = seckey8.get_public_key()

    pubs = [pubkey0, pubkey1, pubkey2, pubkey3, pubkey4, pubkey5,pubkey6, pubkey7]
    secs = [seckey0, seckey1, seckey2, seckey3, seckey4, seckey5,seckey6, seckey7]

    m = 0x800102030405060708090a0b0c0d0e0f800102030405060708090a0b0c0d0e0f.to_bytes(32, 'big')

    i =0
    for pu,pv in zip(pubs,secs):
        print ("%d %s"%(i,pv))
        print ("%d %s"%(i,pu))
        print ("")
        i += 1

    # ring1: 2 keys
    # ring2: 3 keys
    sigma = borromean_sign( [pubkey0, pubkey1,    pubkey2, pubkey3, pubkey4],
                            [         seckey1,    seckey2                  ],
                            [2,3], [1,0], 2,
                           m)

    print("\neO : %s\n"%h(sigma[0]))
    for s in sigma[1]:
         print("si : %s"%h(s))

    assert(borromean_verify([pubkey0, pubkey1,    pubkey2, pubkey3, pubkey4],
                            [2,3], 2,
                            m, sigma))

    # # ring1: 2 keys
    # # ring2: 4 keys
    # pubring1 = pubs[0:2]
    # pubring2 = pubs[2:6]
    # secring1 = secs[0:2]
    # secring2 = secs[2:6]

    # print("ring1 has %d/%d keys"%(len(pubring1),len(secring1)))
    # print("ring2 has %d/%d keys"%(len(pubring2),len(secring2)))
    # for s1 in range(0,len(pubring1)):
    #     for s2 in range(0,len(pubring2)):
    #         print("testing %d %d"%(s1,s2))
    #         pubset = pubring1 + pubring2
    #         secset = [secring1[s1] , secring2[s2]]
    #         secidx = [s1,s2]
    #         rsizes = [len(pubring1), len( pubring2)]
    #         sigma = borromean_sign( pubset, secset,
    #                                 rsizes, secidx, 2,
    #                                 m )
    #         if not borromean_verify( pubset,
    #                                  rsizes, 2,
    #                                  m, sigma) :
    #             print("NOK for %d, %d"%(s1,s2))
    #         else:
    #             print(" OK for %d, %d"%(s1,s2))

