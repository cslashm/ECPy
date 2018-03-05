import hashlib
from ecpy.curves     import Curve,Point
from ecpy.keys       import ECPublicKey, ECPrivateKey
from ecpy.ecdsa  import ECDSA


### ECS
cv     = Curve.get_curve('secp256k1')

pu1_key = ECPublicKey(Point(0x506d1f7347b29aebc45ac079f0f3bc1ee7aa4b0afe8410810fcda3d046dd40d8, 
	                        0x561f37bd6af046807f739e72c53bdf970552d479e241ce1a05370d8c506f47c0,
                            cv))

d = 0x89be3842bf556d2dd47fd16dd3569e4661b33fd58f3d91eab653a7261d442d84

print("%s"%(d*pu1_key.W))
print("%s"%(d*cv.generator))