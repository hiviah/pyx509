
#*    dslib - Python library for Datove schranky
#*    Copyright (C) 2009-2010  CZ.NIC, z.s.p.o. (http://www.nic.cz)
#*
#*    This library is free software; you can redistribute it and/or
#*    modify it under the terms of the GNU Library General Public
#*    License as published by the Free Software Foundation; either
#*    version 2 of the License, or (at your option) any later version.
#*
#*    This library is distributed in the hope that it will be useful,
#*    but WITHOUT ANY WARRANTY; without even the implied warranty of
#*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#*    Library General Public License for more details.
#*
#*    You should have received a copy of the GNU Library General Public
#*    License along with this library; if not, write to the Free
#*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#*
'''
Created on Dec 9, 2009

Verifying RSA signatures.
Uses parts ofcode from  http://stuvel.eu/rsa
'''

# standard library imports
import logging
logger = logging.getLogger('pkcs7.rsa_verifier')
import types
import base64

# dslib imports
from pyasn1.codec.der import decoder
from pyasn1 import error
from dslib.converters.bytes_converter import *

# local imports
from asn1_models.digest_info import *


def _fast_exponentiation(a, p, n):
    """
    Calculates r = a^p mod n
    """
    result = a % n
    remainders = []
    while p != 1:
        remainders.append(p & 1)
        p = p >> 1
    while remainders:
        rem = remainders.pop()
        result = ((a ** rem) * result ** 2) % n
    return result


def _get_hash_from_DER(pkcs1_5_DER_bytes):
    '''
    Decodes DER and returns content of hash component 
    (the hash of the original document)
    '''
    di = DigestInfo()
    digestInfo = decoder.decode(pkcs1_5_DER_bytes, asn1Spec = di)[0]
    hash = digestInfo.getComponentByName("digest")._value
    return hash
    

def _extract_hash_from_decoded_sig(pkcs1_5_encoded_bytes):
    '''
    Returns DER encoded bytes from signature.
    Signature is created according to EMSA-PKCS1-v1_5 :
    shortly: first byte 0x0 | 0x1 | 0*FF .... 0*FF | 0x00 | msg
    msg is DER encoded DigestInfo, which contains hash alg specification
    and the hash itself
    '''
    logger.debug("Decoding RSA EMSA-PKCS-v1.5 encoding scheme")  
    idx = 0
    for byte in pkcs1_5_encoded_bytes:
        if ord(byte) == 0x01 or ord(byte) == 0xff:
            idx += 1
            continue
        if ord(byte) == 0x00:
            idx += 1
            break
    decoded_bytes = pkcs1_5_encoded_bytes[idx:]
    
    return decoded_bytes

def _rsa_decode(encoded, pub_key):
    """
    "Decrypts" RSA signature (applies public exponent modulo n)
    """    
    _enc = bytes_to_int(encoded)
    _mod = bytes_to_int(pub_key["mod"])
    _exp = pub_key["exp"]
    
    rr = _fast_exponentiation(_enc, _exp, _mod)
        
    _decrypt = int_to_bytes(rr)    
    
    return _decrypt
   

def _get_hash_from_signature(signature, pub_key):
    """
    Decodes RSA signature and returns the hash, which was signed
    """
    # decrypt the signature    
    decrypted = _rsa_decode(signature, pub_key)
    # get the DER encoded (DigestInfo component) bytes from the decrypted signature
    decoded_bytes = _extract_hash_from_decoded_sig(decrypted)
    #show_bytes(hash)    
    # get the bytes of the hash
    hash = _get_hash_from_DER(decoded_bytes)
    
    logger.debug("Hash from decoded signature: %s" % base64.b64encode(hash))
        
    return hash


def rsa_verify(data_digest, signature, pub_key):    
    '''
    Verifies data digest against signature with public key
    '''    
    hash_signature = _get_hash_from_signature(signature, pub_key)
    if (data_digest == hash_signature):
        logger.debug("RSA signature OK")
        return True
    else:
        logger.debug("RSA verification failed")
        return False