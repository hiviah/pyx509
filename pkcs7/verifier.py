from certs import cert_finder

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
Verifying of PKCS7 messages
'''

# standard library imports
import logging
logger = logging.getLogger('pkcs7.verifier')
import string

# dslib imports
from pyasn1.codec.der import encoder
from pyasn1 import error
from dslib.certs.cert_finder import *

# local imports
from asn1_models.tools import *
from asn1_models.oid import *
from asn1_models.X509_certificate import *
from asn1_models.pkcs_signed_data import *
from asn1_models.RSA import *
from asn1_models.digest_info import *
from rsa_verifier import *
from debug import *
from digest import *


MESSAGE_DIGEST_KEY = "1.2.840.113549.1.9.4"

def _prepare_auth_attributes_to_digest(auth_attributes_instance):
    """
    Prepares autheticated attributes field to digesting process.
    Replaces implicit tag with SET tag.
    """
    implicit_tag = chr(0xa0)    # implicit tag of the set of authAtt
    set_tag = chr(0x31)         # tag of the ASN type "set"
    
    # encode authentcatdAttributes instance into DER
    attrs = encoder.encode(auth_attributes_instance)
    # remove implicit tag
    if (attrs[0] == implicit_tag):
        attrs = attrs.lstrip(implicit_tag)
        attrs = str(set_tag) + attrs
    
    return attrs

  
def _get_key_material(certificate):
    """
    Extracts public key material and alg. name from certificate.
    Certificate is pyasn1 object Certificate
    """
    pubKey = cert_finder._get_tbs_certificate(certificate).\
            getComponentByName("subjectPublicKeyInfo").\
                getComponentByName("subjectPublicKey")
    
    signing_alg = str(cert_finder._get_tbs_certificate(certificate).\
            getComponentByName("subjectPublicKeyInfo").\
                getComponentByName("algorithm"))
    
    algorithm = None
    if oid_map.has_key(signing_alg):
        algorithm = oid_map[signing_alg]
    
    logger.debug("Extracting key material form public key:")
    
    if (algorithm is None):
        logger.error("Signing algorithm is: unknown OID: %s" % signing_alg)
        raise Exception("Unrecognized signing algorithm")
    else:
        logger.debug("Signing algorithm is: %s" % algorithm)
    
    key_material = None
    if (algorithm == RSA_NAME):
        key_material = get_RSA_pub_key_material(pubKey)
    
    return algorithm, key_material

def _get_digest_algorithm(signer_info):
    '''
    Extracts digest algorithm from signerInfo component.
    Returns algorithm's name or raises Exception
    '''
    digest_alg = str(signer_info.getComponentByName("digestAlg"))
    result = None
    if oid_map.has_key(digest_alg):
        result = oid_map[digest_alg]
    if result is None:
        logger.error("Unknown digest algorithm: %s" % digest_alg)
        raise Exception("Unrecognized digest algorithm")
    
    return result

def _verify_data(data, certificates, signer_infos):
    result = False
    for signer_info in signer_infos:
        id = signer_info.getComponentByName("issuerAndSerialNum").\
                        getComponentByName("serialNumber")._value
        cert = find_cert_by_serial(id, certificates)
        
        if cert is None:
            raise Exception("No certificate found for serial num %d" % id)
        
        sig_algorithm, key_material = _get_key_material(cert) 
        digest_alg = _get_digest_algorithm(signer_info)
                
        auth_attributes = signer_info.getComponentByName("authAttributes")            
        
        if auth_attributes is None:
            data_to_verify = data
        else:
            for attr in auth_attributes:
                # get the messageDigest field of autheticatedAttributes
                type = str(attr.getComponentByName("type"))
                if (type == MESSAGE_DIGEST_KEY):
                    value = str(attr.getComponentByName("value"))
                    # calculate hash of the content of the PKCS7 msg
                    # to compare it with the message digest in authAttr
                    calculated = calculate_digest(data, digest_alg)
                    if (value != calculated):
                        raise Exception("Digest in authenticated attributes differs\
                                        from the digest of message!")
            # prepare authAttributes to verification - change some headers in it
            data_to_verify = _prepare_auth_attributes_to_digest(auth_attributes)
    
        data_to_verify = calculate_digest(data_to_verify, digest_alg)    
        #print base64.b64encode(data_to_verify)    
        signature = signer_info.getComponentByName("signature")._value
    
        if (sig_algorithm == RSA_NAME):
            r = rsa_verify(data_to_verify, signature, key_material)
            if not r:
                logger.debug("Verification of signature with id %d failed"%id)
                return False
            else:
                result = True
        # Note: here we should not have unknown signing algorithm
        # .....only RSA for now
    return result
    
def verify_msg(asn1_pkcs7_msg):
    '''
    Method verifies decoded message (built from pyasn1 objects)
    Input is decoded pkcs7 message.
    '''
    message_content = asn1_pkcs7_msg.getComponentByName("content")
    
    signer_infos = message_content.getComponentByName("signerInfos")    
    certificates = message_content.getComponentByName("certificates")    
    msg = message_content.\
                    getComponentByName("content").\
                        getComponentByName("signed_content").getContentValue()
    
    return _verify_data(msg, certificates, signer_infos)
    

def verify_qts(asn1_qts):
    qts_content = asn1_qts.getComponentByName("content")
    
    signer_infos = qts_content.getComponentByName("signerInfos")
    certificates = qts_content.getComponentByName("certificates")
    msg = qts_content.\
                    getComponentByName("encapsulatedContentInfo").\
                        getComponentByName("eContent")._value
    
    return _verify_data(msg, certificates, signer_infos)
    
