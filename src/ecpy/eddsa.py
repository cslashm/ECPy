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
    """EDDSA signer implemenation according to:
    
     - IETF `draft-irtf-cfrg-eddsa-05 <https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-05>`_.

    Args:
      hasher (hashlib): callable constructor returning an object with update(), digest() interface. Example: hashlib.sha256,  hashlib.sha512...
      fmt (str): in/out signature format. See  :mod:`ecpy.formatters`.
    """
        
    def __init__(self, hasher, fmt="EDDSA"):
        self._hasher = hasher
        self.fmt = fmt
        pass


    @staticmethod
    def get_public_key(pv_key, hasher = hashlib.sha512) :
        """ Returns the public key corresponding to this private key 
        
        This method compute the public key according to draft-irtf-cfrg-eddsa-05.
        
        The hash parameter shall be the same as the one used for signing and
        verifying.
        
        Args:
            hasher (hashlib): callable constructor returning an object with update(), digest() interface. Example: hashlib.sha256,  hashlib.sha512...
            pv_key (ecpy.keys.ECPrivateKey): key to use for signing

        Returns:
           ECPublicKey : public key
        """
        a = EDDSA.get_interal_private_key(pv_key,hasher)
        A = a.d * pv_key.curve.generator
        return   ECPublicKey(A)

    @staticmethod
    def get_interal_private_key(pv_key, hasher = hashlib.sha512) :
        """ Returns the internal private key corresponding to this private key 
        
        Internal private key correspond to the multiplier derived from private
        key and used to compute the public key.
        
        The hash parameter shall be the same as the one used for signing and
        verifying.
        
        Args:
            hasher (hashlib): callable constructor returning an object with update(), digest() interface. Example: hashlib.sha256,  hashlib.sha512...
            pv_key (ecpy.keys.ECPrivateKey): key to use for signing

        Returns:
           ECPrivateKey : internal private key
        """
        curve = pv_key.curve
        n     = curve.order
        size  = curve.size >>3
        
        k = pv_key.d.to_bytes(size,'big')
        hasher = hasher()
        hasher.update(k)
        h = hasher.digest()
        #retrieve encoded pub key
        a = bytearray(h[:32])
        a[0]  &= 0xF8
        a[31] = (a[31] &0x7F) | 0x40
        a = bytes(a)
        a = int.from_bytes(a,'little')
        return   ECPrivateKey(a,pv_key.curve)


    def sign(self, msg, pv_key):
        """ Signs a message.

        Args:
            msg (bytes)                    : the message to sign
            pv_key (ecpy.keys.ECPrivateKey): key to use for signing
        """
        return self._do_sign(msg, pv_key)

    
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
        a = bytearray(h[:32])
        a[0]  &= 0xF8
        a[31] = (a[31] &0x7F) | 0x40
        a = bytes(a)
        a = int.from_bytes(a,'little')
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
            msg (bytes)                   : the message to verify the signature
            sig (bytes)                   : signature to verify
            pu_key (ecpy.keys.ECPublicKey): key to use for verifying
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

        pu = EDDSA.get_public_key(pv_key)
        assert(pu.W == pu_key.W);
        

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





        ### EDDSA
        cv     = Curve.get_curve('Ed25519')

        # public key
        # x: d96878efcfac114929db551927623e574bb552517b0ac585774ae0f1ebf3619
        # y: 2fad0cf5e2bb0303c5074ca3e6aa0a487b27b7577a012176da6983ee85d95ce0

        pu_key = ECPublicKey(Point(0xd96878efcfac114929db551927623e574bb552517b0ac585774ae0f1ebf3619,
                                   0x2fad0cf5e2bb0303c5074ca3e6aa0a487b27b7577a012176da6983ee85d95ce0,
                                   cv))
        # private key
        # s: 5bb7dd30fb4ece686a55faa14e346c08ad81c48c2ebe859a548c101a3dcd360e
        pv_key = ECPrivateKey(0x5bb7dd30fb4ece686a55faa14e346c08ad81c48c2ebe859a548c101a3dcd360e,
                              cv)

        pu = EDDSA.get_public_key(pv_key)
        assert(pu.W == pu_key.W);
        

        # sig:
        # 477dedac6d8332708e00a7c06ceeda54f2086ba73e71e8988b3760ccd23e0c44
        # 08cf09c22ef497328579f6178e8a2a4d611d0c6cce0c684f958d150c5daf4902
        expected_sig = int(0x477dedac6d8332708e00a7c06ceeda54f2086ba73e71e8988b3760ccd23e0c4408cf09c22ef497328579f6178e8a2a4d611d0c6cce0c684f958d150c5daf4902 )
        expected_sig  = expected_sig.to_bytes(64,'big')
        
        #msg:
        # 72
        msg  = int(0xe8898b646cc2274b5daf7fb6e30f738b24203604d7849391056d0fe8093f6693)
        msg  = msg.to_bytes(32,'big')

        signer = EDDSA(hashlib.sha512)
        sig = signer.sign(msg,pv_key)
        assert(sig == expected_sig)

        assert(signer.verify(msg,expected_sig,pu_key))
        
        ##OK!
        print("All internal assert OK!")
    finally:
        pass

