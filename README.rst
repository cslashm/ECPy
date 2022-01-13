ECPy
====

ECPy (pronounced ekpy), is a pure python Elliptic Curve library
providing ECDSA, EDDSA (Ed25519), ECSchnorr, Borromean signatures as well as Point
operations.

Full html documentation is available `here <https://cslashm.github.io/ECPy>`_.


**ECDSA sample**

::

    from ecpy.curves     import Curve,Point
    from ecpy.keys       import ECPublicKey, ECPrivateKey
    from ecpy.ecdsa      import ECDSA

    cv   = Curve.get_curve('secp256k1')
    pu_key = ECPublicKey(Point(0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00,
                           0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f,
                           cv))
    pv_key = ECPrivateKey(0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5,
                      cv)


    signer = ECDSA()
    sig    = signer.sign(b'01234567890123456789012345678912',pv_key)
    assert(signer.verify(b'01234567890123456789012345678912',sig,pu_key))

**Point sample**

::

    from ecpy.curves     import Curve,Point

    cv = Curve.get_curve('secp256k1')
    P  = Point(0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00,
               0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f,
               cv)
    k  = 0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5
    Q  = k*P
    R  = P+Q



History
=======

1.2.5
-----

Fix issue 19

1.2.4
-----

Fix ECDSA when mesaage hash length is greater than domain order length 

Move from distutils to setuptools

1.2.3
-----

Fix ECSchnorr when r is greater than order. Main use case is when
using a hash function with bitlength greater than curve size.

1.2.2
-----

Fix ECDSA with rfc6979. Field was used instead of order for max random.

1.2.1
-----

Missing README update


1.2.0
-----

Fix rfc6979. Now conform to RFC and fully compat with python-ecdsa
(https://github.com/warner/python-ecdsa).


1.1.0
-----

Fix DER encoding for length greater than 128

    Declare ONE infinity point per curve.
    Consider global (non attached to a curve) infinity point as deprecated

Fix infinity point management in ECDSA

Fix issue #13




1.0.1beta
---------

Merge PR11, fixing an overflow with secp521k1


1.0.0beta
---------

Initial 1.x series (Beta)


Quick Install
=============

From Pypi
---------

::

   $ pip install ECPy



From Github
-----------

.. _tarball dist:

From tarball dist
`````````````````
Download last dist tarball.

Untar it

::

    $ tar xzvf ECPy-M.m.tar.gz

install it (or use it as is...)

::

    $ python3 setup.py install

From sources
````````````

Clone the git repository

Rebuild the tarball

::

    $ python3 setup.py sdist

Continue with the created `tarball dist`_.


Generate the documentation
==========================


You can regenerate the doc from git clone

::

    $ cd doc
    $ make singlehtml

Documentation is in build dir

