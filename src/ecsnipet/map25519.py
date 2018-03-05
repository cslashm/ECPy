  
import hashlib
from ecpy.curves     import Curve,Point

cv = Curve.get_curve('Curve25519')
ed = Curve.get_curve('Ed25519')

p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
d = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
a = -1
x = 0x36ab384c9f5a046c3d043b7d1833e7ac080d8e4515d7a45f83c5a14e2843ce0e
y = 0x2260cdf3092329c21da25ee8c9a21f5697390f51643851560e5f46ae6af8a3c9
P = Point(x,y,ed)


B = 1
A = 486662


def inv(x):
    return pow(x%p,p-2,p)

def AB(a,d):
    A = (2*(a+d) * inv(a-d)) % p
    B = (4 * inv(a-d)) % p
    print("A %x"%A)
    print("B %x"%B)

def UV(x,y):
    u = ( (1+y) * inv((1-y)%p)     )%p
    v = ( (1+y) * inv(((1-y)*x)%p) )%p
    return u,v

def XY(u,v):
    x = ( u*inv(v)           ) %p
    y = ( (u-1)*inv((u+1)%p) ) %p
    return (x,y)

AB(a,d)

u,v = UV(x,y)
xx,yy = XY(u,v)
P = Point(xx,yy,ed)
P = Point(u,v,cv)

