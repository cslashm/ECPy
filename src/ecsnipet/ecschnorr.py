import hashlib
from ecpy.curves     import Curve,Point
from ecpy.keys       import ECPublicKey, ECPrivateKey
from ecpy.ecschnorr  import ECSchnorr

### ECS
cv     = Curve.get_curve('secp256k1')
pu_key = ECPublicKey(Point(0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00,

                           0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f,
                           cv))
pv_key = ECPrivateKey(0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5,
                      cv)

#sha256("abc")
msg = int(0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad).to_bytes(32, 'big')

signer = ECSchnorr(hashlib.sha256)

#Sign
k   = int(0xe5a8d1d529971c10ca2af378444fb544a211707892c8898f91dcb171584e3db9)

sig = signer.sign_k(msg,pv_key,k)
print("sig: %x"%int.from_bytes(sig,'big'))
assert(signer.verify(msg,sig,pu_key))

#Sign with krand
#sig = signer.sign(msg,pv_key)
#assert(signer.verify(msg,sig,pu_key))
