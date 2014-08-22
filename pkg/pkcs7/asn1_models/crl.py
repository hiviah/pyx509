
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
Model of CRL
'''

'''
CertificateList  ::=  SEQUENCE  {
        tbsCertList          TBSCertList,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertList  ::=  SEQUENCE  {
        version                 Version OPTIONAL,
                                     -- if present, MUST be v2
        signature               AlgorithmIdentifier,
        issuer                  Name,
        thisUpdate              Time,
        nextUpdate              Time OPTIONAL,
        revokedCertificates     SEQUENCE OF SEQUENCE  {
             userCertificate         CertificateSerialNumber,
             revocationDate          Time,
             crlEntryExtensions      Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }  OPTIONAL,
        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }

'''

# standard library imports
import string

# dslib imports
from pyasn1.type import tag,namedtype,univ,useful
from pyasn1 import error

# local imports
from general_types import *
from X509_certificate import *

class RevokedCertInfo(univ.Sequence):
    '''
    univ.Any type is used instead of this type to avoid
    unnecessary parsing.
    '''
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('userCertificate', CertificateSerialNumber()),
        namedtype.NamedType('revocationDate', Time()),
        namedtype.OptionalNamedType('crlEntryExts', univ.Any())        
        )

class RevokedCertList(univ.Any):
    pass

class TbsCertList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('version', Version()),
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('issuer', Name()),        
        namedtype.NamedType('thisUpdate', Time()),
        namedtype.OptionalNamedType('nextUpdate', Time()),        
        namedtype.OptionalNamedType('revokedCertificates', RevokedCertList()),
        namedtype.OptionalNamedType('crlExtensions', Extensions().\
                                    subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))),
        )


class RevCertificateList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsCertList', TbsCertList()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', ConvertibleBitString())        
        )
