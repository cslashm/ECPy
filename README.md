# ECPy

ECPy (pronounced ekpy), is a pure python Elliptic Curve library providing 
ECDSA, EDDSA, ECSchnorr signatures as well as Point operations.

_ECDSA sample_

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


_Point sample_

    from ecpy.curves     import Curve,Point
    
    cv = Curve.get_curve('secp256k1')
    P  = Point(0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00,
               0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f,
               cv)
    k  = 0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5
    Q  = k*P
    R  = P+Q
    
#Quick Install

Download last dist tarball.

Untar it

    $ tar xzvf ECPy-M.m.tar.gz

install it (or use it as is...)

    $ python3 setup.py install

#Generate the documentation

Online documentation is comming...
You can regenerate the doc from git clone

    $ cd doc
    $ make singlehtml

Documentation is in build dir




