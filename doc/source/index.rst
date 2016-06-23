


Welcome to ECPy's documentation!
=================================

Status
======

| ECPy is in beta stage but already used in some internal tooling.
| Any constructive comment is welcome.

:Version:  0.8
:Authors:  Cedric Mesnil, <cedric.mesnil@ubinity.com>
:License:  Apache 2.0

|

Install
=======

ECPy is originally coded for Python 3, but run under python 2.7 (and maybe 2.6) by using `future`. If you run Python 2, please install the future into the present:

    pip install future

Then install ECPy:

- Rebuild from git clone:
    * python3 setup.py sdist
    * cd dist
    * tar xzvf ECPy-M.m.tar.gz
    * python3 setup install

- Install from dist package:
    * Download last dist tarball
    * tar xzvf ECPy-M.m.tar.gz
    * python3 setup.py install


|

Overview
========

ECPy (pronounced ekpy), is a pure python Elliptic Curve library. It provides
ECDSA, EDDSA, ECSchnorr signature  as well as Point operation.

*ECDSA sample* ::

        from ecpy.curves     import Curve,Point
        from ecpy.keys       import ECPublicKey, ECPrivateKey
        from ecpy.ecdsa      import ECDSA

        cv     = Curve.get_curve('secp256k1')
        pu_key = ECPublicKey(Point(0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00,
                                   
                                   0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f,
                                   cv))
        pv_key = ECPrivateKey(0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5,
                              cv)


        signer = ECDSA()
        sig    = signer.sign(b'01234567890123456789012345678912',pv_key)
        assert(signer.verify(b'01234567890123456789012345678912',sig,pu_key))
                              


*Point sample* ::

        from ecpy.curves     import Curve,Point

        cv = Curve.get_curve('secp256k1')
        P  = Point(0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00,
                   0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f,
                   cv)
        k  = 0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5
        Q  = k*P
        R  = P+Q


Supported Curves & Signature
----------------------------

ECPy support the following curves
   - Short Weierstrass form: y²=x³+a*x+b
   - Twisted Edward a*x²+y2=1+d*x²*y²

See pyec.Curve. get_curve_names

ECPy supports the following 
       
Types
-----

ECPY use binary `bytes` and `int` as primary types.

| `int` are used when scalar is required, as for point coordinate, scalar multiplication, ....
| `bytes` are used when data is required, as hash value, message, ...

Other main types are :py:class:`Point <ecpy.curves.Point>`,  :py:class:`Curve <ecpy.curves.Curve>`,  :py:mod:`Key <ecpy.keys>`,  :py:class:`ECDSA <ecpy.ecdsa.ECDSA>`,  :py:class:`EDDSA <ecpy.eddsa.EDDSA>`, :py:class:`ECSchnorr <ecpy.ecschnorr.ECSchnorr>`. :py:class:`Borromean <ecpy.borromean.Borromean>`.

See API details...


API
===

curves module
-------------

.. automodule:: ecpy.curves
   :show-inheritance:
   :members:
      
keys module
-----------

.. automodule:: ecpy.keys
   :show-inheritance:
   :members:
      
ECDSA module
-------------

.. automodule:: ecpy.ecdsa
   :show-inheritance:
   :members:

EDDSA module
-------------

.. automodule:: ecpy.eddsa
   :show-inheritance:
   :members:

ECSchnorr module
----------------

.. automodule:: ecpy.ecschnorr
   :show-inheritance:
   :members:

Borromean module
----------------

.. automodule:: ecpy.borromean
   :show-inheritance:
   :members:
      
ecrand  module
--------------

.. automodule:: ecpy.ecrand
   :show-inheritance:
   :members:

formatters  module
------------------

.. automodule:: ecpy.formatters
   :show-inheritance:
   :members:

      
Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

