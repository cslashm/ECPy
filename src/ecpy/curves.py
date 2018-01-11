# encoding: UTF-8

# Copyright 2016-2017 Cedric Mesnil <cedric.mesnil@ubinity.com>, Ubinity SAS
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



def decode_scalar_25519(k):
    """ decode scalar according to RF7748 and draft-irtf-cfrg-eddsa

    Args:
           k (bytes) : scalar to decode

    Returns:
          int: decoded scalar
    """
    k = bytearray(k)
    k[0]  &= 0xF8
    k[31] = (k[31] &0x7F) | 0x40
    k = bytes(k)
    k = int.from_bytes(k,'little')
    return k

def encode_scalar_25519(k):
    """ encode scalar according to RF7748 and draft-irtf-cfrg-eddsa

    Args:
           k (int) : scalar to encode

    Returns:
          bytes: encoded scalar
    """
    k.to_bytes(32,'little')
    k = bytearray(k)
    k[0]  &= 0xF8
    k[31] = (k[31] &0x7F) | 0x40
    k = bytes(k)
    return k


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
        if cp['type'] == MONTGOMERY:
            return MontgomeryCurve(cp)
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

    @staticmethod
    def _sqrt(n,p,sign=0):
        """ Generic Tonelli–Shanks algorithm """
        
        #check Euler criterion
        if pow(n,(p-1)//2,p) != 1:
            return None

        #compute square root
        p_1 = p-1
        s = 0
        q = p_1
        while q & 1 == 0:
            q = q>>1
            s  = s+1
        if s == 1:
            r = pow(n,(p+1)//4,p)
        else:
            z = 2
            while pow(z,(p-1)//2,p) == 1:
                z = z+1
            c = pow(z,q,p)
            r = pow(n,(q+1)//2,p)
            t = pow(n,q,p)
            m = s
            while True:
                if t == 1:
                    break
                else:
                    for i in range(1,m):
                        if pow(t,pow(2,i),p) == 1:
                            break
                    b = pow(c,pow(2,m-i-1),p)
                    r = (r*b)   %p
                    t = (t*b*b) %p
                    c = (b*b)   %p
                    m = i
        if sign:
            sign = 1
        if r &1 != sign:
            r = p-r
        return r

    
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
        
        *Note*: you should not use the constructor and only use :func:`Curve.get_curve`
        builder to ensure using supported curve.

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

    def y_recover(self,x,sign=0):
        """ """
        p  = self.field
        y2 = (x*x*x + self.a*x + self.b)%p
        y  = self._sqrt(y2,p,sign)
        return y

    def encode_point(self, P, compressed=False):
        """ Encodes a point P according to *P1363-2000*.
        
        Args:
            P: point to encode

        Returns
           bytes : encoded point [04 | x | y] or [02 | x | sign] 
        """
        size = self.size>>3
        x = bytearray(P.x.to_bytes(size,'big'))
        y = bytearray(P.y.to_bytes(size,'big'))
        if compressed:
            y = [P.y&1]
            enc = [2]
        else:
            enc = [4]
        enc.extend(x)
        enc.extend(y)
        return enc

    def decode_point(self, eP):
        """ Decodes a point P according to *P1363-2000*.
        
        Args:
            eP (bytes)    : encoded point
            curve (Curve) : curve on witch point is
        Returns
           Point : decoded point
        """
        size = self.size>>3
        xy    =  bytearray(eP)
        if xy[0] == 2:
            x = xy[1:1+size]
            x = int.from_bytes(x,'big')
            y = self.y_recover(x,xy[1+size])  
        elif xy[0] == 4:
            x = xy[1:1+size]
            x = int.from_bytes(x,'big')    
            y = xy[1+size:1+size+size]
            y = int.from_bytes(y,'big')    
        else:
            raise ECPyException("Invalid encoded point")
        
        return Point(x,y,self,False)
        
        
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

        *Note*: you should not use the constructor and only use :func:`Curve.get_curve`
        builder to ensure using supported curve.
        
        Args:
           domain (dict): a dictionary providing curve domain parameters
    """

    def __init__(self,domain):
        """ Built an new short twisted Edward curve with the provided parameters.  """
        self._domain = {}
        self._set(domain, ('name','type','size',
                              'a','d','field','generator','order'))

    def _coord_size(self):
        if self.name == 'Ed25519':
            size = 32
        elif self.name == 'Ed448':
            size = 57
        else:
            assert False, '%s not supported'%curve.name
        return size

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
        a = self.a
        d = self.d
        if sign:
            sign = 1
        
        # #x2 = (y^2-1) * (d*y^2-a)^-1
        yy = (y*y)%q
        u = (1-yy)%q
        v = pow(a-d*yy,q-2,q)
        xx = (u*v)%q
        if self.name =='Ed25519':
            x = pow(xx,(q+3)//8,q)
            if (x*x - xx) % q != 0:
                I = pow(2,(q-1)//4,q)
                x = (x*I) % q
        elif self.name =='Ed448':
            x = pow(xx,(q+1)//4,q)      
        else:
            assert False, '%s not supported'%curve.name

        if x &1 != sign:
            x = q-x

        assert (x*x)%q == xx


        # over F(q):
        #     a.xx +yy = 1+d.xx.yy
        # <=> xx(a-d.yy) = 1-yy
        # <=> xx = (1-yy)/(a-d.yy)
        # <=> x = +- sqrt((1-yy)/(a-d.yy))
        # yy   = (y*y)%q
        # u    = (1-yy)%q
        # v    = (a - d*yy)%q
        # v_1 = pow(v, q-2,q)
        # xx = (v_1*u)%q
        # x = self._sqrt(xx,q,sign) # Inherited generic Tonelli–Shanks from Curve 
        return x

    def encode_point(self, P):
        """ Encodes a point P according to *draft_irtf-cfrg-eddsa-04*.
        
        Args:
            P: point to encode

        Returns
           bytes : encoded point
        """
        size = self._coord_size()

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
        sign = y[len(y)-1] & 0x80
        y[len(y)-1] &= ~0x80
        y = int.from_bytes(y,'little')    
        x = self.x_recover(y,sign)
        return Point(x,y,self,True)

    
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
        
      
class MontgomeryCurve(Curve):
    """An elliptic curve defined by the equation: b.y²=x³+a*x²+x.  
    
        The given domain must be a dictionary providing the following keys/values:
              - name (str)         : curve unique name
              - size (int)         : bit size
              - a    (int)         : `a` equation coefficient
              - b    (int)         : `b` equation coefficient
              - field (inf)        : field value 
              - generator (int[2]) : x,y coordinate of generator
              - order (int)        : order of generator

        *Note*: you should not use the constructor and only use :func:`Curve.get_curve`
        builder to ensure using supported curve.

        Args:
           domain (dict): a dictionary providing curve domain parameters
    """

    def __init__(self,domain):
        """ Built an new short twisted Edward curve with the provided parameters.  """
        self._domain = {}
        self._set(domain, ('name','type','size',
                           'a','b','field','generator','order'))
        #inv4 = pow(4,p-2,p)
        #self.a24  = ((self.a+2)*inv4)%p
        self.a24  = (self.a+2)//4

    def is_on_curve(self, P):
        """ See :func:`Curve.is_on_curve` """
        p = self.field
        x = P.x
        right = (x*x*x + self.a*x*x + x)%p
        if P.y:
            y     = P.y
            left  = (self.b*y*y)%p
            return left == right
        else:
            #check equation has a solution according to Euler criterion
            return pow(right,(p-1)//2, p) == 1

    def y_recover(self,x,sign=0):
        """ """
        p  = self.field
        y2 = (x*x*x + self.a*x*x + x)%p
        y  = self._sqrt(y2,p,sign)
        return y
     
    def encode_point(self, P):
        """ Encodes a point P according to *RFC7748*.
        
        Args:
            P: point to encode

        Returns
           bytes : encoded point
        """
        size = self.size>>3
        x = bytearray(P.x.to_bytes(size,'little'))
        return bytes(x)

    def decode_point(self, eP):
        """ Decodes a point P according to *RFC7748*.
        
        Args:
            eP (bytes)    : encoded point
            curve (Curve) : curve on witch point is
        Returns
           Point : decoded point
        """
        x    =  bytearray(eP)
        x[len(x)-1] &= ~0x80
        x = int.from_bytes(x,'little')    
        return Point(x,None,self)

    def mul_point(self,k,P):
        """ See :func:`Curve.add_point` """
        x = self._mul_point_x(k,P.x)
        return Point(x,None, P.curve)
    
    def _mul_point_x(self, k, u):
        """  """        


        k = bin(k)
        k = k[2:]
        sz = len(k)
        x1 = u
        x2 = 1
        z2 = 0
        x3 = u
        z3 = 1
        for i in range(0, sz):
            ki = int(k[i])           
            if ki == 1:
                x3,z3, x2,z2 = self._ladder_step(x1, x3,z3, x2,z2)
            else:
                x2,z2, x3,z3 = self._ladder_step(x1, x2,z2, x3,z3) 
        p = self.field
        zinv = pow(z2,(p - 2),p)
        ku = (x2*zinv)%p
        return ku

    def _ladder_step(self, x_qp, x_p,z_p, x_q,z_q):
        p    = self.field

        t1   = (x_p + z_p)              %p
        t6   = (t1  * t1)               %p
        t2   = (x_p - z_p)              %p
        t7   = (t2  * t2)               %p
        t5   = (t6  - t7)               %p
        t3   = (x_q + z_q)              %p
        t4   = (x_q - z_q)              %p
        t8   = (t4  * t1)               %p
        t9   = (t3  * t2)               %p

        x_pq = ((t8+t9)*(t8+t9))        %p
        z_pq = (x_qp*(t8-t9)*(t8-t9))   %p
        x_2p = (t6*t7)%p                %p
        z_2p = (t5*(t7+self.a24*t5))     %p

        return (x_2p, z_2p, x_pq, z_pq)


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
        self._curve = curve 
        if x:
            self._x = int(x)
        if y :
            self._y = int(y)
        if not x or not y:
            check = False
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
MONTGOMERY     = "montgomery"


curves = [

    {
        'name':      "frp256v1",
        'type':      WEIERSTRASS,
        'size':      256,
        'field':     0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03,
        'generator': (0xB6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF,
                      0x6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB),
        'order':     0xF1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1,
        'cofactor':  1,
        'a':         0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C00,
        'b':         0xEE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F,
        
    },

    {
        'name':      "secp521r1",
        'type':      WEIERSTRASS,
        'size':      521,
        'field':     0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
        'generator': (0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
                      0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650),
        'order':     0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
        'cofactor':  1,
        'a':         0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC,
        'b':         0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
        
    },

    {
        'name':      "secp384r1",
        'type':      WEIERSTRASS,
        'size':      384,
        'field':     0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        'generator': (0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
                      0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f),
        'order':     0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
        'cofactor':  1,
        'a':         0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
        'b':         0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        
    },

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
        'name':      "Brainpool-p512t1",
        'type':      WEIERSTRASS,
        'size':      512,
        'field':     0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3,
        'generator': (0x640ECE5C12788717B9C1BA06CBC2A6FEBA85842458C56DDE9DB1758D39C0313D82BA51735CDB3EA499AA77A7D6943A64F7A3F25FE26F06B51BAA2696FA9035DA,
                      0x5B534BD595F5AF0FA2C892376C84ACE1BB4E3019B71634C01131159CAE03CEE9D9932184BEEF216BD71DF2DADF86A627306ECFF96DBB8BACE198B61E00F8B332),
        'order':     0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069,
        'cofactor':  1,
        'a':         0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F0,
        'b':         0x7CBBBCF9441CFAB76E1890E46884EAE321F70C0BCB4981527897504BEC3E36A62BCDFA2304976540F6450085F2DAE145C22553B465763689180EA2571867423E,
        
    },

    {
        'name':      "Brainpool-p512r1",
        'type':      WEIERSTRASS,
        'size':      512,
        'field':     0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3,
        'generator': (0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822,
                      0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892),
        'order':     0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069,
        'cofactor':  1,
        'a':         0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA,
        'b':         0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723,
        
    },

    {
        'name':      "Brainpool-p384t1",
        'type':      WEIERSTRASS,
        'size':      384,
        'field':     0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53,
        'generator': (0x18DE98B02DB9A306F2AFCD7235F72A819B80AB12EBD653172476FECD462AABFFC4FF191B946A5F54D8D0AA2F418808CC,
                      0x25AB056962D30651A114AFD2755AD336747F93475B7A1FCA3B88F2B6A208CCFE469408584DC2B2912675BF5B9E582928),
        'order':     0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565,
        'cofactor':  1,
        'a':         0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC50,
        'b':         0x7F519EADA7BDA81BD826DBA647910F8C4B9346ED8CCDC64E4B1ABD11756DCE1D2074AA263B88805CED70355A33B471EE,
        
    },
    
    {
        'name':      "Brainpool-p384r1",
        'type':      WEIERSTRASS,
        'size':      384,
        'field':     0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53,
        'generator': (0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E,
                      0x8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315),
        'order':     0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565,
        'cofactor':  1,
        'a':         0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826,
        'b':         0x04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11,
        
    },

    {
        'name':      "Brainpool-p320t1",
        'type':      WEIERSTRASS,
        'size':      320,
        'field':     0xD35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27,
        'generator': (0x925BE9FB01AFC6FB4D3E7D4990010F813408AB106C4F09CB7EE07868CC136FFF3357F624A21BED52,
                      0x63BA3A7A27483EBF6671DBEF7ABB30EBEE084E58A0B077AD42A5A0989D1EE71B1B9BC0455FB0D2C3),
        'order':     0xD35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311,
        'cofactor':  1,
        'a':         0xD35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E24,
        'b':         0xA7F561E038EB1ED560B3D147DB782013064C19F27ED27C6780AAF77FB8A547CEB5B4FEF422340353,
        
    },

    {
        'name':      "Brainpool-p320r1",
        'type':      WEIERSTRASS,
        'size':      320,
        'field':     0xD35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27,
        'generator': (0x43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611,
                      0x14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1),
        'order':     0xD35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311,
        'cofactor':  1,
        'a':         0x3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4,
        'b':         0x520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6,
        
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
        'name':      "Ed448",
        'type':      TWISTEDEDWARD,
        'size':      448,
        'field':     0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        'generator': (0x4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e,
                      0x693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14),
        'order':     0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3,
        'cofactor':  4,
        'd':         0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff6756,
        'a':         1
    },

    {
        'name':      "Ed25519",
        'type':      TWISTEDEDWARD,
        'size':      256,
        'field':     0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed,
        'generator': (15112221349535400772501151409588531511454012693041857206046113283949847762202,
                      46316835694926478169428394003475163141307993866256225615783033603165251855960),
        'order':     0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED,
        'cofactor':  0x08,
        'd':         0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3,
        'a':         -1
    },
 
    {
        'name':      "Curve448",
        'type':      MONTGOMERY,
        'size':      448,
        'field':     0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        'generator': (5,
                      0x7d235d1295f5b1f66c98ab6e58326fcecbae5d34f55545d060f75dc28df3f6edb8027e2346430d211312c4b150677af76fd7223d457b5b1a),
        'order':     0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3,
        'cofactor':  4,
        'b':         1,
        'a':         0x262a6
    },

    {
        'name':      "Curve25519",
        'type':      MONTGOMERY,
        'size':      256,
        'field':     0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed,
        'generator': (9,
                      43114425171068552920764898935933967039370386198203806730763910166200978582548),
        'order':     0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED,
        'cofactor':  0x08,
        'b':         1,
        'a':         486662
    },
]



if __name__ == "__main__":
    try:
        ###############################
        ### Weierstrass quick check ###
        ###############################
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

        #check encoding
        W2_enc = [ 0x04,
                   #x
                   0x07, 0xcd, 0x9e, 0xe7, 0x48, 0xa0, 0xb2, 0x67, 0x73, 0xd9, 0xd2, 0x93, 0x61, 0xf7, 0x55, 0x94,
                   0x96, 0x41, 0x06, 0xd1, 0x3e, 0x1c, 0xad, 0x67, 0xcf, 0xe2, 0xdf, 0x50, 0x3e, 0xe3, 0xe9, 0x0e,
                #y
                   0xd2, 0x09, 0xf7, 0xc1, 0x6c, 0xdb, 0x6d, 0x35, 0x59, 0xbe, 0xa8, 0x8c, 0x7d, 0x92, 0x0f, 0x8f,
                   0xf0, 0x77, 0x40, 0x6c, 0x61, 0x5d, 0xa8, 0xad, 0xfe, 0xcd, 0xee, 0xf6, 0x04, 0xcb, 0x40, 0xa6]
        dW2_enc = [ 0x04,
                    #x
                    0xb4, 0xf2, 0x11, 0xb1, 0x11, 0x66, 0xe6, 0xb3, 0xa3, 0x56, 0x1e, 0x59, 0x78, 0xf4, 0x78, 0x55,
                    0x78, 0x79, 0x43, 0xdb, 0xec, 0xcd, 0x20, 0x14, 0x70, 0x6c, 0x94, 0x1a, 0x58, 0x90, 0xc9, 0x13,
                    #y
                    0xe0, 0x12, 0x2d, 0xc6, 0xf3, 0xce, 0x09, 0x7e, 0xb7, 0x38, 0x65, 0xe6, 0x6a, 0x1c, 0xed, 0x02,
                0xa5, 0x18, 0xaf, 0xde, 0xc0, 0x25, 0x96, 0xd7, 0xd1, 0x52, 0xf1, 0x21, 0x39, 0x1e, 0x2d, 0x63]
        W2_enc_comp = [ 0x02,
                        #x
                        0x07, 0xcd, 0x9e, 0xe7, 0x48, 0xa0, 0xb2, 0x67, 0x73, 0xd9, 0xd2, 0x93, 0x61, 0xf7, 0x55, 0x94,
                        0x96, 0x41, 0x06, 0xd1, 0x3e, 0x1c, 0xad, 0x67, 0xcf, 0xe2, 0xdf, 0x50, 0x3e, 0xe3, 0xe9, 0x0e,
                        #y sign
                        0]
        dW2_enc_comp = [ 0x02,
                        #x
                         0xb4, 0xf2, 0x11, 0xb1, 0x11, 0x66, 0xe6, 0xb3, 0xa3, 0x56, 0x1e, 0x59, 0x78, 0xf4, 0x78, 0x55,
                         0x78, 0x79, 0x43, 0xdb, 0xec, 0xcd, 0x20, 0x14, 0x70, 0x6c, 0x94, 0x1a, 0x58, 0x90, 0xc9, 0x13,
                        #y
                         1]

        P = cv.encode_point(W2)
        assert(P == W2_enc)
        P = cv.decode_point(P)
        assert(P == W2)
        
        P = cv.encode_point(dbl_W2)
        assert(P == dW2_enc)
        P = cv.decode_point(P)
        assert(P == dbl_W2)

        P = cv.encode_point(W2,True)
        assert(P == W2_enc_comp)
        P = cv.decode_point(P)
        assert(P == W2)

        P = cv.encode_point(dbl_W2,True)
        assert(P == dW2_enc_comp)
        P = cv.decode_point(P)
        assert(P == dbl_W2)
        
        
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
        

        ##################################
        ### Montgomery quick check ###
        ##################################
        cv     = Curve.get_curve('Curve25519')

        #0x449a44ba44226a50185afcc10a4c1462dd5e46824b15163b9d7c52f06be346a0
        k = binascii.unhexlify("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        k = decode_scalar_25519(k)
        assert(k == 31029842492115040904895560451863089656472772604678260265531221036453811406496)
        
        eP =  binascii.unhexlify("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        P  = cv.decode_point(eP)
        assert(P.x == 34426434033919594451155107781188821651316167215306631574996226621102155684838)

        eQ = binascii.unhexlify("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        Q  = cv.decode_point(eQ)
        
        kP = k*P
        assert(kP.x == Q.x)
        ekP =  cv.encode_point(kP)
        assert(ekP == eQ)


        #0x4dba18799e16a42cd401eae021641bc1f56a7d959126d25a3c67b4d1d4e96648
        k = binascii.unhexlify("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
        k = decode_scalar_25519(k)
        assert(k == 35156891815674817266734212754503633747128614016119564763269015315466259359304)
        
        eP =  binascii.unhexlify("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
        P  = cv.decode_point(eP)
        assert(P.x == 8883857351183929894090759386610649319417338800022198945255395922347792736741)

        eQ = binascii.unhexlify("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        Q  = cv.decode_point(eQ)
        
        kP = k*P
        assert(kP.x == Q.x)
        ekP =  cv.encode_point(kP)
        assert(ekP == eQ)




        ##OK!
        print("All internal assert OK!")
    finally:
        pass
