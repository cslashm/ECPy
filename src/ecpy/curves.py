# encoding: UTF-8

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


""" Elliptic Curve and Point manipulation

.. moduleauthor:: Cédric Mesnil <cedric.mesnil@ubinity.com>

"""

#python 2 compatibility
from builtins import int,pow

import binascii
import random


class Curve:
    """Elliptic Curve abstraction

    You should not directly create such Object.
    Use `get_curve` to get the predefined curve or create a well-know type
    of curve with your parameters

    Supported well know elliptic curve are:
       - Short Weierstrass form:  y²=x³+a*x+b
       - Twisted Edward          a*x²+y2=1+d*x²*y²

    Attributes:
       name (str)       : curve name, the one given to get_curve or return by get_curve_names
       size (int)       : bit size of curve
       a (int)          : first curve parameter
       b d (int)        : second curve parameter
       field (int)      : curve field
       generator (Point): curve point generator
       order (int)      : order of generator

    """
    
    @staticmethod
    def get_curve(name):
        """Return a Curve object  according to its name
        
       Args:
           name (str) : curve name to retrieve

       Returns:
           Curve:          Curve object
        """
        
        l = [c for c in curves if c['name']==name]
        if len(l) == 0:
            return None
        cp = l[0]
        if cp['type'] == WEIERSTRASS:
            return WeierstrassCurve(cp)
        if cp['type'] == TWISTEDEDWARD:
            return TwistedEdwardCurve(cp)
        return None

    @staticmethod    
    def get_curve_names():
        """ Returns all known curve names

        Returns: 
          tuple:  list of names as str
        """
        return [c['name'] for c in curves]
        
    
    def __init__(self,parameters):        
        raise NotImplementedError('Abstract method __init__')
    
    def _set(self, params, keys):
        for k in keys :
            self._domain[k] = params[k]
        self._domain['name'] = str(self._domain['name'])
        x = self._domain['generator'][0]
        y = self._domain['generator'][1]
        self._domain['generator'] = Point(x,y,self)

        
    def __getattr__(self, name):
        if name in self._domain:
            return self._domain[name]
        raise AttributeError(name)

    def __str__(self):
        return str(self._domain).replace(',','\n')

    def is_on_curve(self, P):
        """Check if P is on this curve 

        This function ignores the default curve attach to P
    
        Args:
            P (Point): Point to check

        Returns:
            bool: True if P is on curve, False else

        """        
        raise NotImplementedError('Abstract method is_on_curve')

    def add_point(self, P,Q):
        """ Returns the sum of P and Q

        This function ignores the default curve attach to P and Q, 
        and assumes P and Q are on this curve.
    
        Args:
            P (Point): first  point to add
            Q (Point): second point to add

        Returns:
            Point: A new Point R = P+Q

        Raises:
             ECPyException : with "Point not on curve", if Point R is not on \
             curve,  thus meaning either P or Q was not on.
        """        
        raise NotImplementedError('Abstract method add_point')
    
    def sub_point(self, P,Q):
        """ Returns the difference of P and Q

        This function ignores the default curve attach to P and Q, 
        and assumes P and Q are on this curve.
    
        Args:
            P (Point): first  point to subtract with
            Q (Point): second point to subtract to

        Returns:
            Point: A new Point R = P-Q

        Raises:
             ECPyException : with "Point not on curve", if Point R is not on \
             curve,  thus meaning either P or Q was not on.
        """        
        return self.add_point(P,Q.neg())

            
    def mul_point(self, k, P):
        """ Returns the scalar multiplication  P with k.

        This function ignores the default curve attach to P and Q, 
        and assumes P and Q are on this curve.
    
        Args:
            P (Point): point to mul_point
            k (int)  : scalar to multiply

        Returns:
            Point: A new Point R = k*Q

        Raises:
            ECPyException : with "Point not on curve", if Point R is not 
            on curve, thus meaning P was not on.

        """        
        raise NotImplementedError('Abstract method mul_point')

    def encode_point(self, P):
        """ encode/compress a point according to its curve"""
        raise NotImplementedError('Abstract method encode_point')
        pass

    def decode_point(self, eP):
        """ decode/decompress a point according to its curve"""
        raise NotImplementedError('Abstract method _point decode_point')
    
        pass


    
class WeierstrassCurve(Curve):
    """An elliptic curve defined by the equation: y²=x³+a*x+b. 

        The given domain must be a dictionary providing the following keys/values:
              - name (str)         : curve unique name
              - size (int)         : bit size
              - a    (int)         : `a` equation coefficient
              - b    (int)         : `b` equation coefficient
              - field (inf)        : field value 
              - generator (int[2]) : x,y coordinate of generator
              - order (int)        : order of generator
              - cofactor (int)     : cofactor
        
        Args:
           domain (dict): a dictionary providing curve parameters

    """
    
    def __init__(self,domain):
        """ Built an new short Weierstrass curve with the provided parameters. """
        self._domain = {}        
        self._set(domain, ('name','type', 'size',
                              'a','b','field','generator','order','cofactor'))

    
    def is_on_curve(self, P):
        """ See :func:`Curve.is_on_curve` """
        q     = self.field
        x     = P.x
        sq3x  = (x*x*x)%q
        y     = P.y
        sqy   = (y*y)%q
        left  = sqy
        right = (sq3x+self.a*x+self.b)%q
        return left == right


    def add_point(self, P,Q):
        """ See :func:`Curve.add_point` """
        q = self.field
        if (P == Q):
            Px,Py,Pz = self._aff2jac(P.x,P.y, q)
            x,y,z = self._dbl_jac(Px,Py,Pz, q,self.a)
        else:
            Px,Py,Pz = self._aff2jac(P.x,P.y, q)
            Qx,Qy,Qz = self._aff2jac(Q.x,Q.y, q)            
            x,y,z = self._add_jac(Px,Py,Pz, Qx,Qy,Qz, q)        
        x,y = self._jac2aff(x,y,z, q)
        PQ = Point(x,y, self)
        return PQ

        
    def mul_point(self, k, P):
        """ See :func:`Curve.mul_point` """
        q = self.field
        a = self.a
        x1,y1,z1 = self._aff2jac(P.x,P.y, q)
        k = bin(k)
        k = k[2:]
        sz = len(k)
        x2,y2,z2 = self._dbl_jac(x1,y1,z1, q,a)
        for i in range(1, sz):
            if k[i] == '1' :
                x1,y1,z1 = self._add_jac(x2,y2,z2, x1,y1,z1, q)
                x2,y2,z2 = self._dbl_jac(x2,y2,z2, q,a)
            else:
                x2,y2,z2 = self._add_jac(x1,y1,z1, x2,y2,z2, q)
                x1,y1,z1 = self._dbl_jac(x1,y1,z1, q,a)
        x,y = self._jac2aff(x1,y1,z1, q)
        return Point(x,y,self)

    @staticmethod
    def _aff2jac(x,y, q):
        return(x,y,1)
    
    @staticmethod
    def _jac2aff(x,y,z, q):
        invz = pow(z,q-2,q)
        sqinvz = (invz*invz)%q
        x = (x*sqinvz)%q
        y = (y*sqinvz*invz)%q
        return (x,y)

    
    @staticmethod
    def _dbl_jac(X1,Y1,Z1, q, a):
        XX   = (X1*X1)%q
        YY   = (Y1*Y1)%q
        YYYY = (YY*YY)%q
        ZZ   = (Z1*Z1)%q
        S    = (2*((X1+YY)*(X1+YY)-XX-YYYY))%q
        M    = (3*XX+a*ZZ*ZZ)%q
        T    = (M*M-2*S)%q
        X3   = (T)%q
        Y3   = (M*(S-T)-8*YYYY)%q
        Z3   = ((Y1+Z1)*(Y1+Z1)-YY-ZZ)%q
        return X3,Y3,Z3
        
    @staticmethod
    def _add_jac(X1,Y1,Z1, X2,Y2,Z2, q):
        Z1Z1 = (Z1*Z1)%q
        Z2Z2 = (Z2*Z2)%q
        U1   = (X1*Z2Z2)%q
        U2   = (X2*Z1Z1)%q
        S1   = (Y1*Z2*Z2Z2)%q
        S2   = (Y2*Z1*Z1Z1)%q
        H    = (U2-U1)%q
        I    = ((2*H)*(2*H))%q
        J    = (H*I)%q
        r    = (2*(S2-S1))%q
        V    = (U1*I)%q
        X3   = (r*r-J-2*V)%q
        Y3   = (r*(V-X3)-2*S1*J)%q
        Z3   = (((Z1+Z2)*(Z1+Z2)-Z1Z1-Z2Z2)*H)%q
        return X3,Y3,Z3

    
class TwistedEdwardCurve(Curve):
    """An elliptic curve defined by the equation: a*x²+y²=1+d*x²*y² 
    
        The given domain must be a dictionary providing the following keys/values:
              - name (str)         : curve unique name
              - size (int)         : bit size
              - a    (int)         : `a` equation coefficient
              - d    (int)         : `b` equation coefficient
              - field (inf)        : field value 
              - generator (int[2]) : x,y coordinate of generator
              - order (int)        : order of generator

        Args:
           domain (dict): a dictionary providing curve domain parameters
    """

    def __init__(self,domain):
        """ Built an new short twisted Edward curve with the provided parameters.  """
        self._domain = {}
        self._set(domain, ('name','type','size',
                              'a','d','field','generator','order'))

    def is_on_curve(self, P):
        """ See :func:`Curve.is_on_curve` """
        q     = self.field
        x     = P.x
        sqx   = (x*x)%q
        y     = P.y
        sqy   = (y*y)%q
        left  = (self.a*sqx+sqy)%q
        right = (1+self.d*sqx*sqy)%q
        return left == right
    
    def x_recover(self, y, sign=0):        
        """ Retrieves the x coordinate according to the y one, \
            such that point (x,y) is on curve.
        
        Args:
            y (int): y coordinate
            sign (int): sign of x

        Returns:
           int: the computed x coordinate
        """
        q = self.field
        d = self.d
        I = pow(2,(q-1)//4,q)

        
        if sign:
            sign = 1
        a = (y*y-1)%q
        b = pow(d*y* y+1,q-2,q)
        xx = (a*b)%q
        x = pow(xx,(q+3)//8,q)
        if (x*x - xx) % q != 0:
            x = (x*I) % q
        if x &1 != sign:
            x = q-x
        return x

    def encode_point(self, P):
        """ Encodes a point P according to *draft_irtf-cfrg-eddsa-04*.
        
        Args:
            P: point to encode

        Returns
           bytes : encoded point
        """
        size = self.size>>3
        y = bytearray(P.y.to_bytes(size,'little'))
        if P.x&1:
            y[len(y)-1] |= 0x80
        return bytes(y)

    def decode_point(self, eP):
        """ Decodes a point P according to *draft_irtf-cfrg-eddsa-04*.
        
        Args:
            eP (bytes)    : encoded point
            curve (Curve) : curve on witch point is
        Returns
           Point : decoded point
        """
        y    =  bytearray(eP)
        sign = y[len(y)-1]
        y[len(y)-1] &= ~0x80
        y = int.from_bytes(y,'little')    
        x = self.x_recover(y,sign)
        return Point(x,y,self,False)

    
    def add_point(self,P,Q):
        """ See :func:`Curve.add_point` """
        q = self.field
        a = self.a
        if (P == Q):
            Px,Py,Pz,Pt = self._aff2ext(P.x,P.y, q)
            x,y,z,t     = self._dbl_ext(Px,Py,Pz,Pt, q,self.a)
        else:
            Px,Py,Pz,Pt = self._aff2ext(P.x,P.y, q)
            Qx,Qy,Qz,Qt = self._aff2ext(Q.x,Q.y, q)
            x,y,z,t     = self._add_ext(Px,Py,Pz,Pt, Qx,Qy,Qz,Qt, q,a)
        x,y = self._ext2aff(x,y,z,t, q)
        return Point(x,y, self)

    def mul_point(self, k, P):
        """ See :func:`Curve.add_point` """
        q = self.field
        a = self.a
        x1,y1,z1,t1 = self._aff2ext(P.x,P.y, q)
        k = bin(k)
        k = k[2:]
        sz = len(k)
        x2,y2,z2,t2 = self._dbl_ext(x1,y1,z1,t1, q,a)
        for i in range(1, sz):
            if k[i] == '1' :
                x1,y1,z1,t1 = self._add_ext(x2,y2,z2,t2, x1,y1,z1,t1, q,a)
                x2,y2,z2,t2 = self._dbl_ext(x2,y2,z2,t2, q,a)
            else:
                x2,y2,z2,t2 = self._add_ext(x1,y1,z1,t1, x2,y2,z2,t2, q,a)
                x1,y1,z1,t1 = self._dbl_ext(x1,y1,z1,t1, q,a)
        x,y = self._ext2aff(x1,y1,z1,t1, q)
        return Point(x,y,self)

    
    @staticmethod
    def _aff2ext(x,y, q):
        rnd = random.getrandbits(300)
        z = 1
        t = (x*y*z) % q
        x = (x*z) % q
        y = (y*z) % q
        return (x,y,z,t)
    
    @staticmethod
    def _ext2aff(x,y,z,xy, q):
        invz = pow(z,q-2,q)
        x = (x*invz)%q
        y = (y*invz)%q
        return (x,y)
    
    @staticmethod
    def _dbl_ext(X1,Y1,Z1,XY1, q,a):
        A  = (X1*X1)%q
        B  = (Y1*Y1)%q
        C  = (2*Z1*Z1)%q
        D  = (a*A)%q
        E  = ((X1+Y1)*(X1+Y1)-A-B)%q
        G  = (D+B)%q
        F  = (G-C)%q
        H  = (D-B)%q
        X3  = (E*F)%q
        Y3  = (G*H)%q
        XY3 = (E*H)%q
        Z3  = (F*G)%q
        return (X3,Y3,Z3,XY3)

    @staticmethod
    def _add_ext(X1,Y1,Z1,XY1,  X2,Y2,Z2,XY2, q,a):
        A = (X1*X2)%q
        B = (Y1*Y2)%q
        C = (Z1*XY2)%q
        D = (XY1*Z2)%q
        E = (D+C)%q
        t0 = (X1-Y1)%q
        t1 = (X2+Y2)%q
        t2 = (t0*t1)%q
        t3 = (t2+B)%q
        F = (t3-A)%q
        t4 = (a*A)%q
        G = (B+t4)%q
        H = (D-C)%q
        X3 = (E*F)%q
        Y3 = (G*H)%q
        XY3 = (E*H)%q
        Z3 = (F*G)%q
        return (X3,Y3,Z3,XY3)
        
    
class Point:
    """Immutable Elliptic Curve Point.

    A Point support the following operator:
    
        - `+` : Point Addition, with automatic doubling support.
        - `*` : Scalar multiplication, can write as k*P or P*k, with P :class:Point and  k :class:int
        - `==`: Point comparison
    
    Attributes:
        x (int)       : Affine x coordinate 
        y (int)       : Affine y coordinate 
        curve (Curve) : Curve on which the point is define


    Args:
        x (int) :     x coordinate
        y (int) :     y coordinate
        check (bool): if True enforce x,y is on curve

    Raises:
        ECPyException : if check=True and x,y is not on curve 
    """

    __slots__ = '_x','_y','_curve'
    
    def __init__(self, x,y, curve, check=True):  
        self._x = int(x)
        self._y = int(y)
        self._curve = curve        
        if check and not curve.is_on_curve(self):
            raise ECPyException("Point not on curve")
        
    @property
    def x(self):
        return self._x

    @property
    def y(self):
        return self._y

    @property
    def curve(self):
        return self._curve
        
    def __neg__(self):
        curve = self.curve
        return Point(self.x,curve.field-self.y,curve)
    
    def __add__(self, Q):
        if isinstance(Q,Point) :
            return self.curve.add_point(self,Q)
        raise NotImplementedError('__add__: type not supported: %s'%type(Q))

    def __sub__(self, Q):
        if isinstance(Q,Point) :
            return self.curve.sub_point(self,Q)
        raise NotImplementedError('__sub__: type not supported: %s'%type(Q))

    def __mul__(self, scal):
        if isinstance(scal,int):
            return self.curve.mul_point(scal,self)
        raise NotImplementedError('__mul__: type not supported: %s'%type(scal))

    def __rmul__(self,scal) :
        return self.__mul__(scal)
    
    def __eq__(self,Q):
        if isinstance(Q,Point) :
            return ((self._curve.name == Q._curve.name or
                     self._curve.name == None or
                     Q._curve.name    == None ) and
                    self._x == Q._x and
                    self._y == Q._y)
        raise NotImplementedError('eq: type not supported: %s'%(type(Q)))

    def __str__(self):
        return "x: %x\n  y: %x" % (self._x,self._y)

    def neg(self):
        return self.__neg__()
        
    def add(self, Q):
        return self.__add__(Q)

    def sub(self, Q):
        return self.__sub__(Q)

    def mul(self, k):
        return self.__mul__(k)
    
    def eq(self,Q):
        return self.__eq__(Q)



class ECPyException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return rept(self.value)



    
WEIERSTRASS   = "weierstrass"
TWISTEDEDWARD = "twistededward"

curves = [
    {
        'name':      "secp256k1",
        'type':      WEIERSTRASS,
        'size':      256,
        'field':     0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
        'generator': (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
                      0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
        'order':     0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
        'cofactor':  1,
        'a':         0,
        'b':         7
        
    },

    {
        'name':      "secp256r1",
        'type':      WEIERSTRASS,
        'size':      256,
        'field':     0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        'generator': (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
        'order':     0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        'cofactor':  0x1,
        'a':         0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
        'b':         0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    },
    
    {
        'name':      "secp224k1",
        'type':      WEIERSTRASS,
        'size':      224,
        'field':     0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D,
        'generator': (0xA1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C,
                      0x7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5),
        'order':     0x010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7,
        'cofactor':  0x1,
        'a':         0x0,
        'b':         0x5,
    },
    
    {
        'name':      "secp224r1",
        'type':      WEIERSTRASS,
        'size':      224,
        'field':     0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001,
        'generator': (0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21 ,
                      0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34),
        'order':     0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D,
        'cofactor':  0x1,
        'a':         0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE,
        'b':         0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
    },
    
    
    {
        'name':      "secp192k1",
        'type':      WEIERSTRASS,
        'size':      192,
        'field':     0xfffffffffffffffffffffffffffffffffffffffeffffee37,
        'generator': (0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d,
                      0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d),
        'order':     0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d,
        'cofactor':  0x1,
        'a':         0x0,
        'b':         0x3
    },
    
    {
        'name':      "secp192r1",
        'type':      WEIERSTRASS,
        'size':      256,
        'field':     0xfffffffffffffffffffffffffffffffeffffffffffffffff,
        'generator': (0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
                      0x7192b95ffc8da78631011ed6b24cdd573f977a11e794811),
        'order':     0xffffffffffffffffffffffff99def836146bc9b1b4d22831,
        'cofactor':  0x1,
        'a':         0xfffffffffffffffffffffffffffffffefffffffffffffffc,
        'b':         0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
    },
    
    
    {
        'name':      "secp160k1",
        'type':      WEIERSTRASS,
        'size':      160,
        'field':     0xfffffffffffffffffffffffffffffffeffffac73,
        'generator': (0x3b4c382ce37aa192a4019e763036f4f5dd4d7ebb,
                      0x938cf935318fdced6bc28286531733c3f03c4fee),
        'order':     0x100000000000000000001b8fa16dfab9aca16b6b3,
        'cofactor':  0x1,
        'a':         0x0,
        'b':         0x7
    },
    
    {
        'name':      "secp160r1",
        'type':      WEIERSTRASS,
        'size':      160,
        'field':     0xffffffffffffffffffffffffffffffff7fffffff,
        'generator': (0x4a96b5688ef573284664698968c38bb913cbfc82,
                      0x23a628553168947d59dcc912042351377ac5fb32),
        'order':     0x100000000000000000001f4c8f927aed3ca752257,
        'cofactor':  0x1,
        'a':         0xffffffffffffffffffffffffffffffff7ffffffc,
        'b':         0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45
    },
    
    {
        'name':      "secp160r2",
        'type':      WEIERSTRASS,
        'size':      160,
        'field':     0xfffffffffffffffffffffffffffffffeffffac73,
        'generator': (0x52dcb034293a117e1f4ff11b30f7199d3144ce6d,
                      0xfeaffef2e331f296e071fa0df9982cfea7d43f2e),
        'order':     0x100000000000000000000351ee786a818f3a1a16b,
        'cofactor':  0x1,
        'a':         0xfffffffffffffffffffffffffffffffeffffac70,
        'b':         0xb4e134d3fb59eb8bab57274904664d5af50388ba
    },
    
    {
        'name':      "Brainpool-p256r1",
        'type':      WEIERSTRASS,
        'size':      256,
        'field':     0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377,
        'generator': (0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262,
                      0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997),
        'order':     0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7,
        'cofactor':  0x1,
        'a':         0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9,
        'b':         0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6
    },
    
    {
        'name':      "Brainpool-p256t1",
        'type':      WEIERSTRASS,
        'size':      256,
        'field':     0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377,
        'generator': (0xa3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f4,
                      0x2d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be),
        'order':     0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7,
        'cofactor':  0x1,
        'a':         0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374,
        'b':         0x662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04
    },
    
    {
        'name':      "Brainpool-p224r1",
        'type':      WEIERSTRASS,
        'size':      224,
        'field':     0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF,
        'generator': (0x0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D,
                      0x58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD),
        'order':     0xD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F,
        'cofactor':  0x1,
        'a':         0x68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43,
        'b':         0x2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B
    },
    
    {
        'name':      "Brainpool-p224t1",
        'type':      WEIERSTRASS,
        'size':      192,
        'a':         0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FC,
        'b':         0x4B337D934104CD7BEF271BF60CED1ED20DA14C08B3BB64F18A60888D,
        'field':     0x2DF271E14427A346910CF7A2E6CFA7B3F484E5C2CCE1C8B730E28B3F,
        'generator': (0x6AB1E344CE25FF3896424E7FFE14762ECB49F8928AC0C76029B4D580,
                      0x0374E9F5143E568CD23F3F4D7C0D4B1E41C8CC0D1C6ABD5F1A46DB4C),
        'order':     0xD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F,
        'cofactor':   0x1,
    },
    
    {
        'name':      "Brainpool-p192r1",
        'type':      WEIERSTRASS,
        'size':      192,
        'field':     0xc302f41d932a36cda7a3463093d18db78fce476de1a86297,
        'generator': (0xc0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6,
                      0x14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f),
        'order':     0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1,
        'cofactor':  0x1,
        'a':         0x6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef,
        'b':         0x469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9
    },
    
    {
        'name':      "Brainpool-p192t1",
        'type':      WEIERSTRASS,
        'size':      192,
        'field':     0xc302f41d932a36cda7a3463093d18db78fce476de1a86297,
        'generator': (0x3ae9e58c82f63c30282e1fe7bbf43fa72c446af6f4618129,
                      0x97e2c5667c2223a902ab5ca449d0084b7e5b3de7ccc01c9),
        'order':     0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1,
        'cofactor':  0x1,
        'a':         0xc302f41d932a36cda7a3463093d18db78fce476de1a86294,
        'b':         0x13d56ffaec78681e68f9deb43b35bec2fb68542e27897b79
    },
    
    {
        'name':      "Brainpool-p160r1",
        'type':      WEIERSTRASS,
        'size':      160,
        'field':     0xe95e4a5f737059dc60dfc7ad95b3d8139515620f,
        'generator': (0xbed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3,
                      0x1667cb477a1a8ec338f94741669c976316da6321),
        'order':     0xe95e4a5f737059dc60df5991d45029409e60fc09,
        'cofactor':  0x1,
        'a':         0x340e7be2a280eb74e2be61bada745d97e8f7c300,
        'b':         0x1e589a8595423412134faa2dbdec95c8d8675e58
    },

    {
        'name':      "Brainpool-p160t1",
        'type':      WEIERSTRASS,
        'size':      160,
        'field':     0xe95e4a5f737059dc60dfc7ad95b3d8139515620f,
        'generator': (0xb199b13b9b34efc1397e64baeb05acc265ff2378,
                      0xadd6718b7c7c1961f0991b842443772152c9e0ad),
        'order':     0xe95e4a5f737059dc60df5991d45029409e60fc09,
        'cofactor':  0x1,
        'a':         0xe95e4a5f737059dc60dfc7ad95b3d8139515620c,
        'b':         0x7a556b6dae535b7b51ed2c4d7daa7a0b5c55f380
    },

    {
        'name':      "NIST-P256",
        'type':      WEIERSTRASS,
        'size':      256,
        'field':     0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        'generator': (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
        'order':     0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        'cofactor':  0x1,
        'a':         0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
        'b':         0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    },

    {
        'name':      "NIST-P224",
        'type':      WEIERSTRASS,
        'size':      224,
        'field':     0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001,
        'generator': (0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21 ,
                      0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34),
        'order':     0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D,
        'cofactor':  0x1,
        'a':         0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE,
        'b':         0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
    },
    
    {
        'name':      "NIST-P192",
        'type':      WEIERSTRASS,
        'size':      192,
        'field':     0xfffffffffffffffffffffffffffffffeffffffffffffffff,
        'generator': (0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
                      0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811),
        'order':     0xffffffffffffffffffffffff99def836146bc9b1b4d22831,
        'cofactor':  0x1,
        'a':         0xfffffffffffffffffffffffffffffffefffffffffffffffc,
        'b':         0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
    },
    
    {
        'name':      "Ed25519",
        'type':      TWISTEDEDWARD,
        'size':      256,
        'field':     0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed,
        'generator': (15112221349535400772501151409588531511454012693041857206046113283949847762202,
                      46316835694926478169428394003475163141307993866256225615783033603165251855960),
        'order':     0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED,
        'd':         0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3,
        'a':         -1
    }
]



if __name__ == "__main__":
    try:
        ### Weierstrass quick check ###
        cv  = Curve.get_curve('secp256k1')
        
        #check generator
        Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
        G = Point(Gx, Gy, cv)
        assert(G == cv.generator)

        #define point    
        W1 = Point(0x6fb13b7e8ab1c7d191d16197c1bf7f8dc7992412e1266155b3fb3ac8b30f3ed8,
                   0x2e1eb77bd89505113819600b395e0475d102c4788a3280a583d9d82625ed8533,
                   cv)
        W2 = Point(0x07cd9ee748a0b26773d9d29361f75594964106d13e1cad67cfe2df503ee3e90e,
                   0xd209f7c16cdb6d3559bea88c7d920f8ff077406c615da8adfecdeef604cb40a6,
                   cv)
        
        #check add
        sum_W1_W2 = Point(0xc4a20cbc2dc27c70fbc1335292c109a1ccd106981b5698feafe702bcb0fb2fca,
                          0x7e1ad514051b87b7ce815c7defcd4fcc01e88842b3135e10a342be49bf5cad09,
                          cv)
        dbl_W2 = Point(0xb4f211b11166e6b3a3561e5978f47855787943dbeccd2014706c941a5890c913,
                       0xe0122dc6f3ce097eb73865e66a1ced02a518afdec02596d7d152f121391e2d63,
                       cv)
        
        s = W1+W2
        assert(s == sum_W1_W2)
        d = W2+W2
        assert(d == dbl_W2)
        
        #check mul
        k = 0x2976F786AE6333E125C0DFFD6C16D37E8CED5ABEDB491BCCA21C75B307D0B318
        kW1 = Point(0x1de93c28f8c58db95f30be1704394f6f5d4602291c4933a1126cc61f9ed70b88,
                    0x6f66df7bb6b37609cacded3052e1d127b47684949dff366020f824d517d66f34,
                    cv)
        mulW1 = k*W1
        assert(kW1 == mulW1)
        
        
        ##################################
        ### Twisted Edward quick check ###
        ##################################
        cv  = Curve.get_curve('Ed25519')
        
        W1 = Point(0x36ab384c9f5a046c3d043b7d1833e7ac080d8e4515d7a45f83c5a14e2843ce0e,
                   0x2260cdf3092329c21da25ee8c9a21f5697390f51643851560e5f46ae6af8a3c9,
                   cv)
        W2 = Point(0x67ae9c4a22928f491ff4ae743edac83a6343981981624886ac62485fd3f8e25c,
                   0x1267b1d177ee69aba126a18e60269ef79f16ec176724030402c3684878f5b4d4,
                   cv)
        
        #check generator
        Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
        By = 46316835694926478169428394003475163141307993866256225615783033603165251855960 
        B = Point(Bx, By, cv)
        assert(B == cv.generator)
        
        #check add
        sum_W1_W2 = Point(0x49fda73eade3587bfcef7cf7d12da5de5c2819f93e1be1a591409cc0322ef233,
                          0x5f4825b298feae6fe02c6e148992466631282eca89430b5d10d21f83d676c8ed,
                          
                          cv)
        dbl_W1 = Point(0x203da8db56cff1468325d4b87a3520f91a739ec193ce1547493aa657c4c9f870,
                       0x47d0e827cb1595e1470eb88580d5716c4cf22832ea2f0ff0df38ab61ca32112f,
                       cv)
        
        s = W1+W2
        assert(s == sum_W1_W2)
        d = W1+W1
        assert(d == dbl_W1)
        
        #check mul
        A = Point(0x74ad28205b4f384bc0813e6585864e528085f91fb6a5096f244ae01e57de43ae,
                  0x0c66f42af155cdc08c96c42ecf2c989cbc7e1b4da70ab7925a8943e8c317403d,
                  cv)
        k  = 0x035ce307f6524510110b4ea1c8af0e81fb705118ebcf886912f8d2d87b5776b3
        kA = Point(0x0d968dd46de0ff98f4a6916e60f84c8068444dbc2d93f5d3b9cf06dade04a994,
                   0x3ba16a015e1dd42b3d088c7a68c344ec47aaba463f67f4e9099c634f64781e00,
                   cv)
        mul = k*A
        assert(mul == kA)
        
        ##OK!
        print("All internal assert OK!")
    finally:
        pass
