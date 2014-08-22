
#*    pyx509 - Python library for parsing X.509
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
Some useful tools for working with ASN1 components.
'''

# dslib imports
from decoder_workarounds import decode
from pyasn1 import error

# local imports
from RSA import RsaPubKey
from DSA import DssParams, DsaPubKey


def tuple_to_OID(tuple):
    """
    Converts OID tuple to OID string
    """
    l = len(tuple)
    buf = ''
    for idx in xrange(l):
        if (idx < l-1):
            buf += str(tuple[idx]) + '.'
        else:
            buf += str(tuple[idx])
    return buf

def get_RSA_pub_key_material(subjectPublicKeyAsn1):
    '''
    Extracts modulus and public exponent from 
    ASN1 bitstring component subjectPublicKey
    '''
    # create template for decoder
    rsa_key = RsaPubKey()
    # convert ASN1 subjectPublicKey component from BITSTRING to octets
    pubkey = subjectPublicKeyAsn1.toOctets()
    
    key = decode(pubkey, asn1Spec=rsa_key)[0]
    
    mod = key.getComponentByName("modulus")._value
    exp = key.getComponentByName("exp")._value
    
    return {'mod': mod, 'exp': exp}
    
def get_DSA_pub_key_material(subjectPublicKeyAsn1, parametersAsn1):
    '''
    Extracts DSA parameters p, q, g from
    ASN1 bitstring component subjectPublicKey and parametersAsn1 from
    'parameters' field of AlgorithmIdentifier.
    '''
    pubkey = subjectPublicKeyAsn1.toOctets()
    
    key = decode(pubkey, asn1Spec=DsaPubKey())[0]
    parameters = decode(str(parametersAsn1), asn1Spec=DssParams())[0]
    paramDict = {"pub": int(key)}
    
    for param in ['p', 'q', 'g']:
        paramDict[param] = parameters.getComponentByName(param)._value
        
    return paramDict
    
