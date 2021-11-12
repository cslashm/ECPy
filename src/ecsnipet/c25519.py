import hashlib, binascii
from ecpy.curves import Curve, Point
import sys


### ECS
cv     = Curve.get_curve('Curve25519')

def t1():
	#k  = 0xa546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
	k  = 31029842492115040904895560451863089656472772604678260265531221036453811406496
	u  = 34426434033919594451155107781188821651316167215306631574996226621102155684838


	ku = cv._mul_point_x(k,u)
	print("ku: %x"%ku)

	v = cv.y_recover(ku)
	P = Point(ku,v,cv)
	eP = cv.encode_point(P)
	print(binascii.hexlify(eP))
	Q = cv.decode_point(eP)
	assert(P.x == Q.x)

def t2():
	kalice  = binascii.unhexlify("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	kalice = cv.decode_scalar_25519(kalice)

	kbob  = binascii.unhexlify("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	kbob = cv.decode_scalar_25519(kbob)

	u  = 9
	G = Point(u,None,cv)

	kaliceG = kalice*G
	print("ALICE")
	print("  k : %.064x"%kalice)
	print("  u : %.064x"%u)
	print("  ku: %.064x"%kaliceG.x)

	kbobG = kbob*G
	print("BOB")
	print("  k : %.064x"%kbob)
	print("  u : %.064x"%u)
	print("  ku: %.064x"%kbobG.x)


	shared1 = kbob*kaliceG
	print("SHARED1")
	print("  X: %.064x"%shared1.x)

	shared2 = kalice*kbobG
	print("SHARED2")
	print("  X: %.064x"%shared2.x)




t2()
