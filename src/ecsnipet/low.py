from ecpy.curves   import Curve,Point

cv  = Curve.get_curve('secp256k1')

k = 2
while True:
    print("k:  %.64x"%k)
    W = k*cv.generator
    if W.x > cv.order:
        break
    k = k+1

print("Wx: %.64x"%W.x)
print("Wy: %.64x"%W.y)

