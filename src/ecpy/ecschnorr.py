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

#python 2 compatibility
from builtins import int,pow

from ecpy.curves     import Curve,Point
from ecpy.keys       import ECPublicKey, ECPrivateKey
from ecpy.formatters import decode_sig, encode_sig
from ecpy            import ecrand

import hashlib

class ECSchnorr:
    """ ECSchnorrSigner
    Conform to `BSI TR 03111  
    <https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_pdf.html>`_
    """

    def __init__(self, hasher):
        self._hasher = hasher
        self.fmt = "DER"
        self.maxtries=10
        pass

    def sign(self, msg, pv_key):
        """ Signs a message hash.

        Args:
            hash_msg (bytes) : the hash of message to sign
            pv_key (ecpy.keys.PrivateKey): key to use for signing
        """
        field = pv_key.curve.field
        for i in range(1,self.maxtries):
            k = ecrand.rnd(field)
            sig = self._do_sign(msg, pv_key,k)
            if sig:
                return sig
        return None

    def sign_k(self, msg, pv_key, k):
        """ Signs a message hash  with provided random

        Args:
            hash_msg (bytes) : the hash of message to sign
            pv_key (ecpy.keys.PrivateKey): key to use for signing
            k (ecpy.keys.PrivateKey): random to use for signing
        """
        return self._do_sign(msg, pv_key,k)
            
    def _do_sign(self, msg, pv_key, k):
        if (pv_key.curve == None):
            raise EcpyException('private key haz no curve')
        curve = pv_key.curve
        n     = curve.order
        G     = curve.generator
        size  = curve.size>>3
        
        Q = G*k
        xQ = (Q.x%n).to_bytes(size,'big')
        
        hasher = self._hasher()
        hasher.update(xQ+msg)
        r = hasher.digest()
        r = int.from_bytes(r,'big')
        r = r%n
        
        s = (k-r*pv_key.d)%n

        return encode_sig(r,s)
            
    def verify(self,msg,sig,pu_key):
        """ Verifies a message signature.                

        Args:
            hash_msg (bytes)      : the hash of message to verify the signature
            sig (bytes)           : signature to verify
            pu_key (key.PublicKey): key to use for verifying
        """
        curve = pu_key.curve
        n     = pu_key.curve.order
        G     = pu_key.curve.generator
        size  = curve.size>>3
        
        r,s = decode_sig(sig, self.fmt)
        if (r == None             or
            r > (pow(2,size*8)-1) or
            s == 0                or
            s > n-1     ) :
            return False
 
        Q = s*G + r*pu_key.W
        xQ = (Q.x%n).to_bytes(size,'big')
        
        hasher = self._hasher()
        hasher.update(xQ+msg)
        v = hasher.digest()
        v = int.from_bytes(v,'big')
        v = r%n
        
        return v == r
 
if __name__ == "__main__":
    try:
        ### ECS
        cv     = Curve.get_curve('secp256k1')
        pu_key = ECPublicKey(Point(0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00,
                                   
                                   0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f,
                                   cv))
        pv_key = ECPrivateKey(0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5,
                              cv)

        #sha256("abc")
        msg = int(0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad)
        msg  = msg.to_bytes(32,'big')

        signer = ECSchnorr(hashlib.sha256)

        #Sign 
        k   = int(0xe5a8d1d529971c10ca2af378444fb544a211707892c8898f91dcb171584e3db9)

        sig = signer.sign_k(msg,pv_key,k)
        assert(signer.verify(msg,sig,pu_key))        

        #Sign with krand
        sig = signer.sign(msg,pv_key)
        assert(signer.verify(msg,sig,pu_key))        

        ##OK!
        print("All internal assert OK!")
    finally:
        pass
