import hashlib
from ecpy.curves     import Curve,Point
from ecpy.keys       import ECPublicKey, ECPrivateKey
from ecpy.ecdsa  import ECDSA



#pvkey:
#  f028458b39af92fea938486ecc49562d0e7731b53d9b25e2701183e4f2adc991
#Hash:
#  8c7632afe967e2e16ae7f39dc32c252b3d751fa6e01daa0efc3c174e230f4617
#Signer's public: 04
#  81bc1f9486564d3d57a305e8f9067df2a7e1f007d4af4fed085aca139c6b9c7a
#  8e3f35e4d7fb27a56a3f35d34c8c2b27cd1d266d5294df131bf3c1cbc39f5a91
#App signature:
#  304402203a329589dbc6f3bb88bf90b45b5d4935a18e13e2cb8fcee0b94b3102ec19645702202f61af55df0e56e71d40a9f5f111faeb2f831c1fd314c55227ac44110fb33049



### ECS
# test key
cv     = Curve.get_curve('secp256k1')
pv_key = ECPrivateKey(0xf028458b39af92fea938486ecc49562d0e7731b53d9b25e2701183e4f2adc991,cv)
pu_key = ECPublicKey(Point(0x81bc1f9486564d3d57a305e8f9067df2a7e1f007d4af4fed085aca139c6b9c7a,
                           0x8e3f35e4d7fb27a56a3f35d34c8c2b27cd1d266d5294df131bf3c1cbc39f5a91,
                           cv))


k = pv_key.get_public_key()
assert(k.W.x == pu_key.W.x)
assert(k.W.y == pu_key.W.y)

print("Public key ok")

msg = 0x8c7632afe967e2e16ae7f39dc32c252b3d751fa6e01daa0efc3c174e230f4617
msg = msg.to_bytes(32,'big')

sig = 0x304402203a329589dbc6f3bb88bf90b45b5d4935a18e13e2cb8fcee0b94b3102ec19645702202f61af55df0e56e71d40a9f5f111faeb2f831c1fd314c55227ac44110fb33049
sig = sig.to_bytes(70,'big')

## verify
signer = ECDSA()

while True:
    sig = signer.sign(msg,pv_key)
    signer.verify(msg,sig,pu_key)

assert(signer.verify(msg,sig,pu_key))        
