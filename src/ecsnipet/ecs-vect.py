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

msg = int(0x0101010101010101010101010101010101010101010101010101010101010101)
msg  = msg.to_bytes(32,'big')

k = int(0x4242424242424242424242424242424242424242424242424242424242424242)


print("ISO")
signer = ECSchnorr(hashlib.sha256,"ISO","ITUPLE")
sig = signer.sign_k(msg,pv_key,k)
print
assert(signer.verify(msg,sig,pu_key))

print("ISOx")
signer = ECSchnorr(hashlib.sha256,"ISOx","ITUPLE")
sig = signer.sign_k(msg,pv_key,k)
assert(signer.verify(msg,sig,pu_key))

print("BSI")
signer = ECSchnorr(hashlib.sha256,"BSI","ITUPLE")
sig = signer.sign_k(msg,pv_key,k)
assert(signer.verify(msg,sig,pu_key))

print("LIBSECP")
signer = ECSchnorr(hashlib.sha256,"LIBSECP","ITUPLE")
sig = signer.sign_k(msg,pv_key,k)
assert(signer.verify(msg,sig,pu_key))
