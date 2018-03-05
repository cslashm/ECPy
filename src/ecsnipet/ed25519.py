from ecpy.curves     import Curve,Point
ed = Curve.get_curve('Ed25519')

points = (
(0x2657b0657076d1a06becd2d9140aaa789ff605cf7a521c170587f9581c97b1f8,  #Py
 0x7808bee43e05caed6b84465285bbfbeec62a61b6063df506f4248cca3adb673f), #8Py
(0x3d03f6888c987e79a0ca6331741a0972c373277d00b7fbf7d4b16f67a8355570,  #Py
 0x3efd96f5feeb68f781e4a400519430b2496118e6eb021c5f1523a9310260f5e0)  #8Py
)


order = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
for W in points :
    print("-------------------------------------------------")
    print("Input point\n  y': %x"% W[0])
    
    Py = W[0].to_bytes(32,"big")
    P = ed.decode_point(Py)
    print("Point has been decoded")
    print("  %s"%P)
    
    print ("Expected result is\n   y': %x" % W[1])

    print()
    print ("Compute 8.P")
    k = 8;
    Q = k*P
    print("  %s"%Q)

    print ("Encode 8.P")
    Q = ed.encode_point(Q)
    Qy =  int.from_bytes(Q,'big')

    print("result is  %x"%Qy)
    if Qy == W[1]:
        print('==> success')
    else:
        print('==> fail')
    
        print()
    print ("Compute (8+k*order).P")
    k = 8 + ((1249543*8)*order)//8;
    Q = k*P
    print("  %s"%Q)
    print ("Encode 8.P")
    Q = ed.encode_point(Q)
    Qy =  int.from_bytes(Q,'big')

    print("result is  %x"%Qy)
    if Qy == W[1]:
        print('==> success')
    else:
        print('==> fail')
    

    
