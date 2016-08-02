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

def list_formats():
    return ("DER","BTUPLE","ITUPLE","RAW","EDDSA")

def encode_sig(r,s,fmt="DER",size=0) :
    """ encore signature according format

    Args:
        r (int):   r value
        s (int):   s value
        fmt (str): 'DER'|'BTUPLE'|'ITUPLE'|'RAW'|'EDDSA

    Returns:
         bytes:  TLV   for DER encoding
    Returns:
         bytes:  (r,s) for BTUPLE encoding
    Returns:
         ints:   (r,s) for ITUPLE encoding
    Returns:
         bytes:  r|s   for RAW encoding
    """
    
    if fmt=="DER":        
        r = r.to_bytes((r.bit_length()+7)//8, 'big')
        s = s.to_bytes((s.bit_length()+7)//8, 'big')
        if (r[0] & 0x80) == 0x80 :
            r = b'\0'+r
        if (s[0] & 0x80) == 0x80 :
            s = b'\0'+s
        sig = (b'\x30'+int((len(r)+len(s)+4)).to_bytes(1,'big') +
               b'\x02'+int(len(r)).to_bytes(1,'big') + r        +
               b'\x02'+int(len(s)).to_bytes(1,'big') + s      )
        return sig

    if fmt=="BTUPLE":
        r = r.to_bytes((r.bit_length()+7)//8, 'big')
        s = s.to_bytes((s.bit_length()+7)//8, 'big')
        return (r,s)

    if fmt=="ITUPLE":
        return (r,s)
    
    if fmt=="RAW":
        if size == 0:
            raise ECPyException("size must be specified when encoding in RAW")
        r = r.to_bytes(size, 'big')
        s = s.to_bytes(size, 'big')
        return r+s

    if fmt=="EDDSA":
        if size == 0:
            raise ECPyException("size must be specified when encoding in EDDSA")
        r = r.to_bytes(size, 'little')
        s = s.to_bytes(size, 'little')
        return r+s

    
def decode_sig(sig,fmt="DER") :
    """ encore signature according format

    Args:
        rs (bytes,ints,tuple) : r,s value       
        fmt (str): 'DER'|'BTUPLE'|'ITUPLES'|'RAW'|'EDDSA'

    Returns:       
       ints:   (r,s) 
    """

    
    if fmt=="DER":
        sig_len  = sig[1]+2
        r_offset = 4
        r_len    = sig[3]
        s_offset = 4+r_len+2
        s_len    = sig[4+r_len+1]
        if ( sig[0]  != 0x30          or
             sig_len != r_len+s_len+6 or
             sig[r_offset-2] != 0x02  or 
             sig[s_offset-2] != 0x02  ):
            return None,None
        r = int.from_bytes(sig[r_offset:r_offset+r_len], 'big')
        s = int.from_bytes(sig[s_offset:s_offset+s_len], 'big')                
        return r,s
    
    if fmt=="ITUPLE":        
        return (sig[0],sig[1])

    if fmt=="BTUPLE":        
        r = int.from_bytes(sig[0], 'big')
        s = int.from_bytes(sig[1], 'big')                
        return r,s

    if fmt=="RAW":
        l = len(sig)>>1
        r = int.from_bytes(sig[0:l], 'big')
        s = int.from_bytes(sig[l:],  'big')
        return r,s

    if fmt=="EDDSA":
        l = len(sig)>>1
        r = int.from_bytes(sig[0:l], 'little')
        s = int.from_bytes(sig[l:],  'little')
        return r,s
