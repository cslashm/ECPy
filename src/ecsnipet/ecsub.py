from ecpy.curves     import Curve,Point
ed = Curve.get_curve('Ed25519')


P = Point( 0x3f14cc3324c79d9687f95c8f75af102eaebc1f7670a80b1f6a07959e3698afe9, 0x4a927deb79b86633dc86a0ea061ef34276dc20d736a7b47fc926e54cf4ea5e32,ed )
Q = Point( 0x34a511dbf0b36780d8c785ecc2857525bc990a6df9803c68b8af302be00c104c, 0x417587b30efdc587244a8609934a5ce39bf2986de45706810b0c0e314bc961f5,ed  )

print('-------------------------------------------------')

y = int.from_bytes(ed.encode_point(P),'big')
print("P %s"%hex(y))
y = int.from_bytes(ed.encode_point(Q),'big')
print("Q %s"%hex(y))



print('-------------------------------------------------')

Q_ = Point(ed.field - Q.x,  Q.y, ed)

Z = P+Q_
print(Z)

y = int.from_bytes(ed.encode_point(Z),'big')
print(hex(y))
    
print('-------------------------------------------------')

print('-------------------------------------------------')

Q_ = Point(Q.x,  ed.field - Q.y, ed)

Z = P+Q_
print(Z)

y = int.from_bytes(ed.encode_point(Z),'big')
print(hex(y))