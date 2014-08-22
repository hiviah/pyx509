
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
Module for parsing dmQTimestamp.
dmQtimestamp is base64 encoded DER pkcs7 document containing
signedData component, so it is the same format as the format
of signed data message. Version of content is '3', so there are small
differences.
'''

# standard library imports
import logging
logger = logging.getLogger("pkcs7.tstamp_helper")
import base64

# dslib imports
from dslib.certs.cert_finder import *
from dslib import models

# local imports
import pkcs7_decoder
import verifier


def parse_qts(dmQTimestamp, verify=False):
    '''
    Parses QTimestamp and verifies it.
    Returns result of verification and TimeStampTOken instance.
    '''    
    ts = base64.b64decode(dmQTimestamp)
    
    qts = pkcs7_decoder.decode_qts(ts)
    verif_result = None
    #if we want to verify the timestamp
    if (verify):
        verif_result = verifier.verify_qts(qts)        
        if verif_result:
            logger.info("QTimeStamp verified")
        else:
            logger.error("QTimeStamp verification failed")
    else:
        logger.info("Verification of timestamp skipped")
        
    tstData = qts.getComponentByName("content").getComponentByName("encapsulatedContentInfo").getComponentByName("eContent")._value    
    tstinfo = pkcs7_decoder.decode_tst(tstData)
    
    t = models.TimeStampToken(tstinfo)
    
    certificates = qts.getComponentByName("content").getComponentByName("certificates")
    # get the signer info and attach signing certificates to the TSTinfo
    signer_infos = qts.getComponentByName("content").getComponentByName("signerInfos")
    for signer_info in signer_infos:
      id = signer_info.getComponentByName("issuerAndSerialNum").\
                        getComponentByName("serialNumber")._value
      cert = find_cert_by_serial(id, certificates)
      if cert is None:
        logger.error("No certificate found for timestamp signer")
        continue           
      
      t.asn1_certificates.append(cert)

    return verif_result, t
