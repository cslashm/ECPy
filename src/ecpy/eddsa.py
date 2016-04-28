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


from ecpy.curves import Curve,Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.formatters import decode_sig, encode_sig
import hashlib

class EDDSA:
    """EDDSA Signer
    
    Conform to `draft-irtf-cfrg-eddsa-05 <https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-05>`_.

    Args:
      hasher (hashlib): callable constructor returning an object with update(), digest() interface. Example: hashlib.sha256,  hashlib.sha512...
    """
        
    def __init__(self, hasher):
        self._hasher = hasher
        self.fmt="EDDSA"
        pass

    def sign(self, msg, pv_key):
        """ Signs a message.

        Args:
            msg (bytes)            : the message to sign
            pv_key (key.PrivateKey): key to use for signing
        """
        return self._do_sign(hash_msg, pv_key)

    
    def _do_sign(self,msg,pv_key):
        curve = pv_key.curve
        B     = curve.generator
        n     = curve.order
        size = curve.size >>3
        
        k = pv_key.d.to_bytes(size,'big')
        hasher = self._hasher()
        hasher.update(k)
        h = hasher.digest()
        
        #retrieve encoded pub key
        a = bytearray(h[size-1::-1])
        a[0]  &= ~0x40;
        a[0]  |= 0x40;
        a[31] &= 0xF8;
        a = bytes(a)
        a = int.from_bytes(a,'big')
        A = a * B
        eA = curve.encode_point(A)
        #OK
        
        #compute R
        hasher = self._hasher()         
        hasher.update(h[size:]+msg)
        r = hasher.digest()
        r = int.from_bytes(r,'little')
        r = r % n
        R = r*B
        eR = curve.encode_point(R)
                           
        #compute S
        hasher = self._hasher()
        hasher.update(eR+eA+msg)
        H_eR_eA_m = hasher.digest()
        i = int.from_bytes(H_eR_eA_m, 'little')
        S = (r + i*a)%n

        #S = S.to_bytes(size,'little')

        #return eR+S
        eR = int.from_bytes(eR,'little')
        sig = encode_sig(eR,S,self.fmt,size)
        return sig
    
    def verify(self,msg,sig,pu_key):
        """ Verifies a message signature.                

        Args:
            msg (bytes)           : the message to verify the signature
            sig (bytes)           : signature to verify
            pu_key (key.PublicKey): key to use for verifying
        """
        curve = pu_key.curve
        n     = curve.order
        size  = curve.size>>3

        #eR = sig[0:size]
        #S  = int.from_bytes(sig[size:],'little')
        eR,S = decode_sig(sig, self.fmt)

        #left
        eR = eR.to_bytes(size,'little')
        R  = curve.decode_point(eR)
        
        hasher = self._hasher()
        eA = curve.encode_point(pu_key.W)
        hasher.update(eR+eA+msg)
        h = hasher.digest()
        h = int.from_bytes(h,'little')
        h = h%n
        A = pu_key.W        
        left  = R+h*A

        #right
        right = S*curve.generator
        
        return left == right


    
if __name__ == "__main__":
    try:
        ### EDDSA
        cv     = Curve.get_curve('Ed25519')

        # public key
        # x: 74ad28205b4f384bc0813e6585864e528085f91fb6a5096f244ae01e57de43ae
        # y: 0c66f42af155cdc08c96c42ecf2c989cbc7e1b4da70ab7925a8943e8c317403d


        pu_key = ECPublicKey(Point(0x74ad28205b4f384bc0813e6585864e528085f91fb6a5096f244ae01e57de43ae,
                                   0x0c66f42af155cdc08c96c42ecf2c989cbc7e1b4da70ab7925a8943e8c317403d,
                                   cv))
        # private key
        # s: 0x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
        pv_key = ECPrivateKey(0x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb,
                              cv)

        # sig:
        # 0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da
        # 0x085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
        expected_sig = int(0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00)
        expected_sig  = expected_sig.to_bytes(64,'big')
        
        #msg:
        # 72
        msg  = int(0x72)
        msg  = msg.to_bytes(1,'big')

        signer = EDDSA(hashlib.sha512)

        sig = signer.sign(msg,pv_key)
        assert(sig == expected_sig)
        
        assert(signer.verify(msg,expected_sig,pu_key))


        ##OK!
        print("All internal assert OK!")
    finally:
        pass

