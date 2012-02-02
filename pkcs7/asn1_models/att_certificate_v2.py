
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
import string

# dslib imports
from pyasn1.type import tag,namedtype,univ
from pyasn1 import error

# local imports
from X509_certificate import *
from general_types import *
from oid import oid_map as oid_map
'''
ASN.1 modules from http://www.ietf.org/rfc/rfc3281.txt
'''


'''
   ObjectDigestInfo ::= SEQUENCE {
                 digestedObjectType  ENUMERATED {
                         publicKey            (0),
                         publicKeyCert        (1),
                         otherObjectTypes     (2) },
                                 -- otherObjectTypes MUST NOT
                                 -- be used in this profile
                 otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
                 digestAlgorithm     AlgorithmIdentifier,
                 objectDigest        BIT STRING
            }

'''
class ObjectDigestInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.OptionalNamedType("digestedObjectType", univ.Enumerated()),
                        namedtype.OptionalNamedType("otherObjectTypeID", univ.ObjectIdentifier()),
                        namedtype.OptionalNamedType("digestAlgorithm", AlgorithmIdentifier()),
                        namedtype.OptionalNamedType("objectDigest", ConvertibleBitString()),
                        )
'''
 IssuerSerial  ::=  SEQUENCE {
                 issuer         GeneralNames,
                 serial         CertificateSerialNumber,
                 issuerUID      UniqueIdentifier OPTIONAL
            }

'''
class IssuerSerial(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.NamedType("issuer", GeneralNames()),
                        namedtype.NamedType("serial", CertificateSerialNumber()),
                        namedtype.OptionalNamedType("issuerUID", UniqueIdentifier()),                        
                        )

'''
Holder ::= SEQUENCE {
                  baseCertificateID   [0] IssuerSerial OPTIONAL,
                           -- the issuer and serial number of
                           -- the holder's Public Key Certificate
                  entityName          [1] GeneralNames OPTIONAL,
                           -- the name of the claimant or role
                  objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
                           -- used to directly authenticate the holder,
                           -- for example, an executable
            }
'''
class Holder(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.OptionalNamedType("baseCertificateID", IssuerSerial().\
                                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))),
                        namedtype.OptionalNamedType("entityName", GeneralNames().\
                                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))),                               
                        namedtype.OptionalNamedType("objectDigestInfo", ObjectDigestInfo().\
                                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x2))),                        
                        )
'''
 AttCertIssuer ::= CHOICE {
                   v1Form   GeneralNames,  -- MUST NOT be used in this
                                           -- profile
                   v2Form   [0] V2Form     -- v2 only
             }

             V2Form ::= SEQUENCE {
                   issuerName            GeneralNames  OPTIONAL,
                   baseCertificateID     [0] IssuerSerial  OPTIONAL,
                   objectDigestInfo      [1] ObjectDigestInfo  OPTIONAL
                      -- issuerName MUST be present in this profile
                      -- baseCertificateID and objectDigestInfo MUST
                      -- NOT be present in this profile
             }
'''
class V2Form(univ.Sequence):
   componentType = namedtype.NamedTypes(
                        namedtype.OptionalNamedType("issuerName", GeneralNames()),
                        namedtype.OptionalNamedType("basicCertificateID", IssuerSerial()\
                                            .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))), 
                        namedtype.OptionalNamedType("objectDigestInfo", ObjectDigestInfo()\
                                            .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))), 
                    
                        ) 

class AttCertIssuer(univ.Choice):
   componentType = namedtype.NamedTypes(
                        namedtype.NamedType("v1Form", GeneralNames()),
                        namedtype.NamedType("v2Form", V2Form()\
                                            .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))), 
                        )                                            
    

class AttrCertAttributes(univ.SequenceOf):
    pass


'''
 AttributeCertificateInfo ::= SEQUENCE {
                 version              AttCertVersion -- version is v2,
                 holder               Holder,
                 issuer               AttCertIssuer,
                 signature            AlgorithmIdentifier,
                 serialNumber         CertificateSerialNumber,
                 attrCertValidityPeriod   AttCertValidityPeriod,
                 attributes           SEQUENCE OF Attribute,
                 issuerUniqueID       UniqueIdentifier OPTIONAL,
                 extensions           Extensions OPTIONAL
            }

'''
class ACInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.DefaultedNamedType("version", Version('v2')),
                        namedtype.NamedType("holder", Holder()),                                             
                        namedtype.NamedType("issuer", AttCertIssuer()), 
                        namedtype.NamedType("signature", AlgorithmIdentifier()),
                        namedtype.NamedType("serialNumber", CertificateSerialNumber()),
                        namedtype.NamedType("attrCertValidityPeriod", Validity()),
                        namedtype.NamedType("attributes", AttrCertAttributes()),
                        namedtype.OptionalNamedType("issuerUniqueID", UniqueIdentifier()),
                        namedtype.OptionalNamedType("extensions", Extensions()),
                        )


class AttributeCertificateV2(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.NamedType("acInfo", ACInfo()),
                        namedtype.NamedType("sigAlg", AlgorithmIdentifier()),                                             
                        namedtype.NamedType("signature", ConvertibleBitString()) 
                        )



class CertificateChoices(univ.Choice):
    componentType = namedtype.NamedTypes(
                        namedtype.NamedType("certificate", Certificate()),
                        namedtype.NamedType("extendedC", Certificate().\
                                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))),
                        namedtype.NamedType("v1AttrCert", AttributeCertificateV2().\
                                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))),
                        namedtype.NamedType("v2AttrCert", univ.Sequence().\
                                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x2))),
                        namedtype.NamedType("otherCert", univ.Sequence().\
                                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x3)))
                        )


class CertificateSet(univ.SetOf):
    componentType = CertificateChoices()
