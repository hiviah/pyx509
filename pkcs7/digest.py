
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

# standard library imports
import hashlib
import logging
logger = logging.getLogger("pkcs7.digest")
import base64

RSA_NAME = "RSA"
SHA1_NAME = "SHA-1"
SHA256_NAME = "SHA-256"
SHA384_NAME = "SHA-384"
SHA512_NAME = "SHA-512"

def calculate_digest(data, alg):    
    '''
    Calculates digest according to algorithm
    '''
    digest_alg = None
    if (alg == SHA1_NAME):
        digest_alg = hashlib.sha1() 
    
    if (alg == SHA256_NAME):
        digest_alg = hashlib.sha256()
    
    if (alg == SHA384_NAME):
        digest_alg = hashlib.sha384()
    
    if (alg == SHA512_NAME):
        digest_alg = hashlib.sha512()
    
    if digest_alg is None:
        logger.error("Unknown digest algorithm : %s" % alg)
        return None
    
    digest_alg.update(data)   
    dg = digest_alg.digest()       
    
    logger.debug("Calculated hash from input data: %s" % base64.b64encode(dg))    
    return dg
