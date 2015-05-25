
#*    pyx509 - Python library for parsing X.509
#*    Copyright (C) 2009-2012  CZ.NIC, z.s.p.o. (http://www.nic.cz)
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
Created on Dec 11, 2009

'''

from pyasn1.error import PyAsn1Error
from pkcs7.asn1_models.tools import *
from pkcs7.asn1_models.oid import *
from pkcs7.asn1_models.tools import *
from pkcs7.asn1_models.X509_certificate import *
from pkcs7.asn1_models.certificate_extensions import *
from pkcs7.debug import *
from pkcs7.asn1_models.decoder_workarounds import decode
import datetime, time
import collections, struct


class CertificateError(Exception):
    pass
    

class Name():
    '''
    Represents Name (structured, tagged).
    This is a dictionary. Keys are types of names (mapped from OID to name if
    known, see _oid2Name below, otherwise numeric). Values are arrays containing
    the names that mapped to given type (because having more values of one type,
    e.g. multiple CNs is common).
    '''
    _oid2Name = {
        "2.5.4.3": "CN",
        "2.5.4.6": "C",
        "2.5.4.7": "L",
        "2.5.4.8": "ST",
        "2.5.4.10": "O",
        "2.5.4.11": "OU",
        
        "2.5.4.45": "X500UID",
        "1.2.840.113549.1.9.1": "email",
        "2.5.4.17": "zip",
        "2.5.4.9": "street",
        "2.5.4.15": "businessCategory",
        "2.5.4.5": "serialNumber",
        "2.5.4.43": "initials",
        "2.5.4.44": "generationQualifier",
        "2.5.4.4": "surname",
        "2.5.4.42": "givenName",
        "2.5.4.12": "title",
        "2.5.4.46": "dnQualifier",
        "2.5.4.65": "pseudonym",
        "0.9.2342.19200300.100.1.25": "DC",
    }
    
    def __init__(self, name):
        self.__attributes = {}
        for name_part in name:
            for attr in name_part:
                type = str(attr.getComponentByPosition(0).getComponentByName('type'))                
                value = str(attr.getComponentByPosition(0).getComponentByName('value'))
                
                #use numeric OID form only if mapping is not known
                typeStr = Name._oid2Name.get(type) or type
                values = self.__attributes.get(typeStr)
                if values is None:
                    self.__attributes[typeStr] = [value]
                else:
                    values.append(value)
    
    def __str__(self):
        ''' Returns the Distinguished name as string. The string for the same
        set of attributes is always the same.
        '''
        #There is no consensus whether RDNs in DN are ordered or not, this way
        #we will have all sets having same components mapped to identical string.
        valueStrings = []
        for key in sorted(self.__attributes.keys()):
            values = sorted(self.__attributes.get(key))
            valuesStr = ", ".join(["%s=%s" % (key, value) for value in values])
            valueStrings.append(valuesStr)
        
        return ", ".join(valueStrings)
            
        
    def get_attributes(self):
        return self.__attributes.copy()

class ValidityInterval():
    '''
    Validity interval of a certificate. Values are UTC times.
    Attributes:
    -valid_from
    -valid_to
    '''
    def __init__(self, validity):
        self.valid_from = self._getGeneralizedTime(
            validity.getComponentByName("notBefore"))
        self.valid_to = self._getGeneralizedTime(
            validity.getComponentByName("notAfter"))
        
    def get_valid_from_as_datetime(self):
      return self.parse_date(self.valid_from)
    
    def get_valid_to_as_datetime(self):
      return self.parse_date(self.valid_to)
       
    @staticmethod
    def _getGeneralizedTime(timeComponent):
        """Return time from Time component in YYYYMMDDHHMMSSZ format"""
        if timeComponent.getName() == "generalTime": #from pkcs7.asn1_models.X509_certificate.Time
            #already in YYYYMMDDHHMMSSZ format
            return timeComponent.getComponent()._value
        else: #utcTime
            #YYMMDDHHMMSSZ format
            #UTCTime has only short year format (last two digits), so add
            #19 or 20 to make it "full" year; by RFC 5280 it's range 1950..2049
            timeValue = timeComponent.getComponent()._value
            shortyear = int(timeValue[:2])
            return (shortyear >= 50 and "19" or "20") + timeValue
            
    @classmethod
    def parse_date(cls, date):
        """
        parses date string and returns a datetime object;
        """
        year = int(date[:4])
        month = int(date[4:6])
        day = int(date[6:8])
        hour = int(date[8:10])
        minute = int(date[10:12])
        try:
            #seconds must be present per RFC 5280, but some braindead certs
            #omit it
            second = int(date[12:14])
        except (ValueError, IndexError):
            second = 0
        return datetime.datetime(year, month, day, hour, minute, second)

class PublicKeyInfo():
    '''
    Represents information about public key.
    Expects RSA or DSA.
    Attributes:
    - alg (OID string identifier of algorithm)
    - key (dict of parameter name to value; keys "mod", "exp" for RSA and
        "pub", "p", "q", "g" for DSA)
    - algType - one of the RSA, DSA "enum" below
    '''
    UNKNOWN = -1
    RSA = 0
    DSA = 1
    
    def __init__(self, public_key_info):
        algorithm = public_key_info.getComponentByName("algorithm")
        parameters = algorithm.getComponentByName("parameters")
        
        self.alg = str(algorithm)
        bitstr_key = public_key_info.getComponentByName("subjectPublicKey")
        
        if self.alg == "1.2.840.113549.1.1.1":
            self.key = get_RSA_pub_key_material(bitstr_key)
            self.algType = PublicKeyInfo.RSA
            self.algName = "RSA"
        elif self.alg == "1.2.840.10040.4.1":
            self.key = get_DSA_pub_key_material(bitstr_key, parameters)
            self.algType = PublicKeyInfo.DSA
            self.algName = "DSA"
        else:
            self.key = {}
            self.algType = PublicKeyInfo.UNKNOWN
            self.algName = self.alg

class SubjectAltNameExt():
    '''
    Subject alternative name extension.
    '''
    def __init__(self, asn1_subjectAltName):
        # Creates a dictionary for the component types found in
        # SubjectAltName. Each dictionary entry is a list of names
        self.values = collections.defaultdict(list)
        for gname in asn1_subjectAltName:
            component_type = gname.getName()
            if component_type == 'iPAddress':
                name = self.mk_ip_addr(gname.getComponent())
            else:
                name = unicode(gname.getComponent())
            self.values[component_type].append(name)

    def mk_ip_addr(self, octets):
        # Converts encoded ipv4 or ipv6 octents into printable strings.
        octet_len = len(octets)
        octets_as_ints = struct.unpack("B"*octet_len, str(octets))
        if octet_len == 4:
            octets_as_str = map(str, octets_as_ints)
            return ".".join(octets_as_str)
        else:
            # IPV6 style addresses
            # See http://tools.ietf.org/html/rfc2373#section-2.2
            to_hex = lambda x: "%02X" % x
            address_chunks = ["".join(map(to_hex, octets_as_ints[x:x+2]))
                              for x in range(octet_len / 2)]
            return ":".join(address_chunks)



class BasicConstraintsExt():
    '''
    Basic constraints of this certificate - is it CA and maximal chain depth.
    '''
    def __init__(self, asn1_bConstraints):
        self.ca = bool(asn1_bConstraints.getComponentByName("ca")._value)
        self.max_path_len = None
        if asn1_bConstraints.getComponentByName("pathLen") is not None:
            self.max_path_len = asn1_bConstraints.getComponentByName("pathLen")._value
        

class KeyUsageExt():
    '''
    Key usage extension. 
    '''    
    def __init__(self, asn1_keyUsage):
        self.digitalSignature = False    # (0),
        self.nonRepudiation = False     # (1),
        self.keyEncipherment = False    # (2),
        self.dataEncipherment = False   # (3),
        self.keyAgreement = False       # (4),
        self.keyCertSign = False        # (5),
        self.cRLSign = False            # (6),
        self.encipherOnly = False       # (7),
        self.decipherOnly = False       # (8) 
        
        bits = asn1_keyUsage._value
        try:
            if (bits[0]): self.digitalSignature = True
            if (bits[1]): self.nonRepudiation = True
            if (bits[2]): self.keyEncipherment = True
            if (bits[3]): self.dataEncipherment = True
            if (bits[4]): self.keyAgreement = True
            if (bits[5]): self.keyCertSign = True
            if (bits[6]): self.cRLSign = True    
            if (bits[7]): self.encipherOnly = True
            if (bits[8]): self.decipherOnly = True
        except IndexError:
            return

class ExtendedKeyUsageExt():
    '''
    Extended key usage extension.
    '''    
    #The values of the _keyPurposeAttrs dict will be set to True/False as
    #attributes of this objects depending on whether the extKeyUsage lists them.
    _keyPurposeAttrs = {
        "1.3.6.1.5.5.7.3.1": "serverAuth",
        "1.3.6.1.5.5.7.3.2": "clientAuth",
        "1.3.6.1.5.5.7.3.3": "codeSigning",
        "1.3.6.1.5.5.7.3.4": "emailProtection",
        "1.3.6.1.5.5.7.3.5": "ipsecEndSystem",
        "1.3.6.1.5.5.7.3.6": "ipsecTunnel",
        "1.3.6.1.5.5.7.3.7": "ipsecUser",
        "1.3.6.1.5.5.7.3.8": "timeStamping",
    }
    
    def __init__(self, asn1_extKeyUsage):
        usageOIDs = set([tuple_to_OID(usageOID) for usageOID in asn1_extKeyUsage])
        
        for (oid, attr) in ExtendedKeyUsageExt._keyPurposeAttrs.items():
            setattr(self, attr, oid in usageOIDs)

class AuthorityKeyIdExt():
    '''
    Authority Key identifier extension.
    Identifies key of the authority which was used to sign this certificate.
    '''
    def __init__(self, asn1_authKeyId):
        if (asn1_authKeyId.getComponentByName("keyIdentifier")) is not None:
            self.key_id = asn1_authKeyId.getComponentByName("keyIdentifier")._value
        if (asn1_authKeyId.getComponentByName("authorityCertSerialNum")) is not None:
            self.auth_cert_sn = asn1_authKeyId.getComponentByName("authorityCertSerialNum")._value
        if (asn1_authKeyId.getComponentByName("authorityCertIssuer")) is not None:
            issuer = asn1_authKeyId.getComponentByName("authorityCertIssuer")
            iss = str(issuer.getComponentByName("name"))
            self.auth_cert_issuer = iss
    
class SubjectKeyIdExt():
    '''
    Subject Key Identifier extension. Just the octet string.
    '''
    def __init__(self, asn1_subKey):
        self.subject_key_id = asn1_subKey._value
      
class PolicyQualifier():
    '''
    Certificate policy qualifier. Consist of id and
    own qualifier (id-qt-cps | id-qt-unotice).
    '''
    def __init__(self, asn1_pQual):
        self.id = tuple_to_OID(asn1_pQual.getComponentByName("policyQualifierId"))
        if asn1_pQual.getComponentByName("qualifier") is not None:
            qual = asn1_pQual.getComponentByName("qualifier")
            self.qualifier = None
            # this is a choice - only one of following types will be non-null
            
            comp = qual.getComponentByName("cpsUri")
            if comp is not None:
                self.qualifier = str(comp)
            # not parsing userNotice for now
            #comp = qual.getComponentByName("userNotice")
            #if comp is not None:
            #    self.qualifier = comp
            
class AuthorityInfoAccessExt():
    '''
    Authority information access.
    Instance variables:
    - id - accessMethod OID as string
    - access_location as string
    - access_method as string if the OID is known (None otherwise)
    '''
    _accessMethods = {
        "1.3.6.1.5.5.7.48.1": "ocsp",
        "1.3.6.1.5.5.7.48.2": "caIssuers",
    }
    
    def __init__(self, asn1_authInfo):
        self.id = tuple_to_OID(asn1_authInfo.getComponentByName("accessMethod"))
        self.access_location = str(asn1_authInfo.getComponentByName("accessLocation").getComponent())
        self.access_method = AuthorityInfoAccessExt._accessMethods.get(self.id)
        pass
    
class CertificatePolicyExt():
    '''
    Certificate policy extension.
    COnsist of id and qualifiers.
    '''
    def __init__(self, asn1_certPol):
        self.id = tuple_to_OID(asn1_certPol.getComponentByName("policyIdentifier"))
        self.qualifiers = []
        if (asn1_certPol.getComponentByName("policyQualifiers")):
            qualifiers = asn1_certPol.getComponentByName("policyQualifiers")
            self.qualifiers = [PolicyQualifier(pq) for pq in qualifiers]

class Reasons():
    '''
    CRL distribution point reason flags
    '''
    def __init__(self, asn1_rflags):
        self.unused  = False   #(0),
        self.keyCompromise = False   #(1),
        self.cACompromise = False   #(2),
        self.affiliationChanged = False    #(3),
        self.superseded = False   #(4),
        self.cessationOfOperation = False   #(5),
        self.certificateHold = False   #(6),
        self.privilegeWithdrawn = False   #(7),
        self.aACompromise = False   #(8) 
        
        bits = asn1_rflags._value
        try:
            if (bits[0]): self.unused = True
            if (bits[1]): self.keyCompromise = True
            if (bits[2]): self.cACompromise = True
            if (bits[3]): self.affiliationChanged = True
            if (bits[4]): self.superseded = True
            if (bits[5]): self.cessationOfOperation = True
            if (bits[6]): self.certificateHold = True    
            if (bits[7]): self.privilegeWithdrawn = True
            if (bits[8]): self.aACompromise = True
        except IndexError:
            return


class CRLdistPointExt():
    '''
    CRL distribution point extension
    '''
    def __init__(self, asn1_crl_dp):
        dp = asn1_crl_dp.getComponentByName("distPoint")
        if dp is not None:
            #self.dist_point = str(dp.getComponent())
            self.dist_point = str(dp.getComponentByName("fullName")[0].getComponent())
        else:
            self.dist_point = None
        reasons = asn1_crl_dp.getComponentByName("reasons")
        if reasons is not None:
            self.reasons = Reasons(reasons)
        else:
            self.reasons = None
        issuer = asn1_crl_dp.getComponentByName("issuer")
        if issuer is not None:
            self.issuer = str(issuer)
        else:
            self.issuer = None

class QcStatementExt():
    '''
    id_pe_qCStatement
    '''
    def __init__(self, asn1_caStatement):
        self.oid = str(asn1_caStatement.getComponentByName("stmtId"))
        self.statementInfo = asn1_caStatement.getComponentByName("stmtInfo")
        if self.statementInfo is not None:
            self.statementInfo = str(self.statementInfo)
        
class PolicyConstraintsExt:
    def __init__(self, asn1_policyConstraints):
        self.requireExplicitPolicy = None
        self.inhibitPolicyMapping = None
        
        requireExplicitPolicy = asn1_policyConstraints.getComponentByName("requireExplicitPolicy")
        inhibitPolicyMapping = asn1_policyConstraints.getComponentByName("inhibitPolicyMapping")
        
        if requireExplicitPolicy is not None:
            self.requireExplicitPolicy = requireExplicitPolicy._value
        
        if inhibitPolicyMapping is not None:
            self.inhibitPolicyMapping = inhibitPolicyMapping._value
        
class NameConstraint:
    def __init__(self, base, minimum, maximum):
        self.base = base
        self.minimum = minimum
        self.maximum = maximum
    
    def __repr__(self):
        return "NameConstraint(base: %s, min: %s, max: %s)" % (repr(self.base), self.minimum, self.maximum)

    def __str__(self):
        return self.__repr__()

class NameConstraintsExt:
    def __init__(self, asn1_nameConstraints):
        self.permittedSubtrees = []
        self.excludedSubtrees = []
        
        permittedSubtrees = asn1_nameConstraints.getComponentByName("permittedSubtrees")
        excludedSubtrees = asn1_nameConstraints.getComponentByName("excludedSubtrees")
        
        self.permittedSubtrees = self._parseSubtree(permittedSubtrees)
        self.excludedSubtrees = self._parseSubtree(excludedSubtrees)
    
    def _parseSubtree(self, asn1Subtree):
        if asn1Subtree is None:
            return []
            
        subtreeList = []
        
        for subtree in asn1Subtree:
            #TODO: somehow extract the fucking type of GeneralName
            base = subtree.getComponentByName("base").getComponent()#ByName("dNSName")
            if base is None:
                continue
            
            base = str(base)
            
            minimum = subtree.getComponentByName("minimum")._value
            maximum = subtree.getComponentByName("maximum")
            if maximum is not None:
                maximum = maximum._value
            
            subtreeList.append(NameConstraint(base, minimum, maximum))
            
        return subtreeList
        
        
class NetscapeCertTypeExt:
    def __init__(self, asn1_netscapeCertType):
        #https://www.mozilla.org/projects/security/pki/nss/tech-notes/tn3.html
        bits = asn1_netscapeCertType._value
        self.clientCert = len(bits) > 0 and bool(bits[0])
        self.serverCert = len(bits) > 1 and bool(bits[1])
        self.caCert = len(bits) > 5 and bool(bits[5])
        
class SignedCertificateTimestamp:

    def __init__(self, version, logID, timestamp, extensions, hash_alg, sig_alg, signature):
        self.version = version
        self.logID = logID
        self.timestamp = timestamp
        self.extensions = extensions
        self.hash_alg = hash_alg
        self.sig_alg = sig_alg
        self.signature = signature

class SCTListExt():
    '''
    SignedCertificateTimestampList extension for Certificate Transparency (RFC 6962)
    '''
    #Structure of SignedCertificateTimestampList from RFC 6962:
    #
    #    2 bytes size of sct_list
    #        2 bytes SerializedSCT size
    #            1 byte  sct_version
    #           32 bytes log id
    #            8 bytes timestamp - milliseconds from epoch
    #            2 bytes extensions length
    #                n bytes extension data
    #            1 byte  hash algo
    #            1 byte  signature algo
    #            2 byte  signature length
    #                n bytes signature

    def __init__(self, asn1_sctList):
        data = asn1_sctList._value
        self.scts = []

        # This parsing is ugly, but we can't use pyasn1 - 
        # the data is serialized according to RFC 5246.
        packed_len, data = self._splitBytes(data, 2)
        total_len = struct.unpack("!H", packed_len)[0]
        if len(data) != total_len:
            raise ValueError("Malformed length of SCT list")
        bytes_read = 0

        while bytes_read < total_len:
            packed_len, data = self._splitBytes(data, 2)
            sct_len = struct.unpack("!H", packed_len)[0]

            bytes_read += sct_len + 2
            sct_data, data  = self._splitBytes(data, sct_len)
            packed_vlt, sct_data = self._splitBytes(sct_data,  41)
            version, logid, timestamp = struct.unpack("!B32sQ", packed_vlt)
            timestamp = datetime.datetime.fromtimestamp(timestamp/1000.0)

            packed_len, sct_data = self._splitBytes(sct_data, 2)
            ext_len = struct.unpack("!H", packed_len)[0]
            extensions, sct_data = self._splitBytes(sct_data, ext_len)

            hash_alg, sig_alg, sig_len = struct.unpack("!BBH", sct_data[:4])
            signature = sct_data[4:]
            if len(signature) != sig_len:
                raise ValueError("SCT signature has incorrect length, expected %d, got %d" % (sig_len, len(signature)))
 
            self.scts.append(SignedCertificateTimestamp(version, logid, timestamp, extensions, hash_alg, sig_alg, signature))

    @staticmethod
    def _splitBytes(buf, count):
        """ 
        Split buf into two strings (part1, part2) where part1 has count bytes.
        @raises ValueError if buf is too short.
        """
        if len(buf) < count:
            raise ValueError("Malformed structure encountered when parsing SCT, expected %d bytes, got only %d" % (count, len(buf)))

        return buf[:count], buf[count:]
      
class ExtensionType:
    '''"Enum" of extensions we know how to parse.'''
    SUBJ_ALT_NAME = "subjAltNameExt"
    AUTH_KEY_ID = "authKeyIdExt"
    SUBJ_KEY_ID = "subjKeyIdExt"
    BASIC_CONSTRAINTS = "basicConstraintsExt"
    KEY_USAGE = "keyUsageExt"
    EXT_KEY_USAGE = "extKeyUsageExt"
    CERT_POLICIES = "certPoliciesExt"
    CRL_DIST_POINTS = "crlDistPointsExt"
    STATEMENTS = "statemetsExt"
    AUTH_INFO_ACCESS = "authInfoAccessExt"
    POLICY_CONSTRAINTS = "policyConstraintsExt"
    NAME_CONSTRAINTS = "nameConstraintsExt"
    NETSCAPE_CERT_TYPE = "netscapeCertTypeExt"
    SCT_LIST = "sctListExt"
    
class ExtensionTypes:
    #hackish way to enumerate known extensions without writing them twice
    knownExtensions = [name for (attr, name) in vars(ExtensionType).items() if attr.isupper()]
    
class Extension():
    '''
    Represents one Extension in X509v3 certificate
    Attributes:
    - id  (identifier of extension)
    - is_critical
    - value (value of extension, needs more parsing - it is in DER encoding)
    '''
    #OID: (ASN1Spec, valueConversionFunction, attributeName)
    _extensionDecoders = {
        "2.5.29.17": (GeneralNames(),                 lambda v: SubjectAltNameExt(v),                 ExtensionType.SUBJ_ALT_NAME),
        "2.5.29.35": (KeyId(),                        lambda v: AuthorityKeyIdExt(v),                 ExtensionType.AUTH_KEY_ID),
        "2.5.29.14": (SubjectKeyId(),                 lambda v: SubjectKeyIdExt(v),                   ExtensionType.SUBJ_KEY_ID),
        "2.5.29.19": (BasicConstraints(),             lambda v: BasicConstraintsExt(v),               ExtensionType.BASIC_CONSTRAINTS),
        "2.5.29.15": (None,                           lambda v: KeyUsageExt(v),                       ExtensionType.KEY_USAGE),
        "2.5.29.32": (CertificatePolicies(),          lambda v: [CertificatePolicyExt(p) for p in v], ExtensionType.CERT_POLICIES),
        "2.5.29.31": (CRLDistributionPoints(),        lambda v: [CRLdistPointExt(p) for p in v],      ExtensionType.CRL_DIST_POINTS),
        "1.3.6.1.5.5.7.1.3": (Statements(),           lambda v: [QcStatementExt(s) for s in v],       ExtensionType.STATEMENTS),
        "1.3.6.1.5.5.7.1.1": (AuthorityInfoAccess(),  lambda v: [AuthorityInfoAccessExt(s) for s in v], ExtensionType.AUTH_INFO_ACCESS),
        "2.5.29.37": (ExtendedKeyUsage(),             lambda v: ExtendedKeyUsageExt(v),               ExtensionType.EXT_KEY_USAGE),
        "2.5.29.36": (PolicyConstraints(),            lambda v: PolicyConstraintsExt(v),              ExtensionType.POLICY_CONSTRAINTS),
        "2.5.29.30": (NameConstraints(),              lambda v: NameConstraintsExt(v),                ExtensionType.NAME_CONSTRAINTS),
        "2.16.840.1.113730.1.1": (NetscapeCertType(), lambda v: NetscapeCertTypeExt(v),               ExtensionType.NETSCAPE_CERT_TYPE),
        "1.3.6.1.4.1.11129.2.4.2": (SCTList(),        lambda v: SCTListExt(v),                        ExtensionType.SCT_LIST),
    }
    
    def __init__(self, extension):
        self.id = tuple_to_OID(extension.getComponentByName("extnID"))
        critical = extension.getComponentByName("critical")
        self.is_critical = (critical != 0)
        self.ext_type = None
        
        # set the bytes as the extension value
        self.value = extension.getComponentByName("extnValue")._value
        
        # if we know the type of value, parse it
        decoderTuple = Extension._extensionDecoders.get(self.id)
        if decoderTuple is not None:
            try:
                (decoderAsn1Spec, decoderFunction, extType) = decoderTuple
                v = decode(self.value, asn1Spec=decoderAsn1Spec)[0]
                self.value = decoderFunction(v)
                self.ext_type = extType
            except PyAsn1Error:
                #According to RFC 5280, unrecognized extension can be ignored
                #unless marked critical, though it doesn't cover all cases.
                if self.is_critical:
                    raise
        elif self.is_critical:
            raise CertificateError("Critical extension OID %s not understood" % self.id)

class Certificate():
    '''
    Represents Certificate object.
    Attributes:
    - version
    - serial_number
    - signature_algorithm (data are signed with this algorithm)
    - issuer (who issued this certificate)
    - validity
    - subject (for who the certificate was issued)
    - pub_key_info 
    - issuer_uid (optional)
    - subject_uid (optional)
    - extensions (list of extensions)
    '''
    def __init__(self, tbsCertificate):
        self.version = tbsCertificate.getComponentByName("version")._value
        self.serial_number = tbsCertificate.getComponentByName("serialNumber")._value
        self.signature_algorithm = str(tbsCertificate.getComponentByName("signature"))
        self.issuer = Name(tbsCertificate.getComponentByName("issuer"))
        self.validity = ValidityInterval(tbsCertificate.getComponentByName("validity"))
        self.subject = Name(tbsCertificate.getComponentByName("subject"))
        self.pub_key_info = PublicKeyInfo(tbsCertificate.getComponentByName("subjectPublicKeyInfo"))
        
        issuer_uid = tbsCertificate.getComponentByName("issuerUniqueID")
        if issuer_uid:
            self.issuer_uid = issuer_uid.toOctets()
        else:
            self.issuer_uid = None
            
        subject_uid = tbsCertificate.getComponentByName("subjectUniqueID")
        if subject_uid:
            self.subject_uid = subject_uid.toOctets()
        else:
            self.subject_uid = None
            
        self.extensions = self._create_extensions_list(tbsCertificate.getComponentByName('extensions'))
        
        #make known extensions accessible through attributes
        for extAttrName in ExtensionTypes.knownExtensions:
            setattr(self, extAttrName, None)
        for ext in self.extensions:
            if ext.ext_type:
                setattr(self, ext.ext_type, ext)
    
    def _create_extensions_list(self, extensions):
        if extensions is None:
            return []
        
        return [Extension(ext) for ext in extensions]
    
class X509Certificate():
    '''
    Represents X509 certificate.
    Attributes:
    - signature_algorithm (used to sign this certificate)
    - signature
    - tbsCertificate (the certificate)
    '''
    
    def __init__(self, certificate):
        self.signature_algorithm = str(certificate.getComponentByName("signatureAlgorithm"))
        self.signature = certificate.getComponentByName("signatureValue").toOctets()     
        tbsCert = certificate.getComponentByName("tbsCertificate")
        self.tbsCertificate = Certificate(tbsCert)   
        self.verification_results = None
        self.raw_der_data = "" # raw der data for storage are kept here by cert_manager
        self.check_crl = True
    
    def is_verified(self, ignore_missing_crl_check=False):
      '''
      Checks if all values of verification_results dictionary are True,
      which means that the certificate is valid
      '''
      return self._evaluate_verification_results(
                        self.verification_results,
                        ignore_missing_crl_check=ignore_missing_crl_check)
    
    def valid_at_date(self, date, ignore_missing_crl_check=False):
      """check validity of all parts of the certificate with regard
      to a specific date"""
      verification_results = self.verification_results_at_date(date)
      return self._evaluate_verification_results(
                        verification_results,
                        ignore_missing_crl_check=ignore_missing_crl_check)
    
    def _evaluate_verification_results(self, verification_results,
                                       ignore_missing_crl_check=False):
      if verification_results is None:
        return False
      for key, value in verification_results.iteritems():
        if value:
          pass
        elif ignore_missing_crl_check and key=="CERT_NOT_REVOKED" and \
             value is None:
          continue
        else:
          return False
      return True
      
    
    def verification_results_at_date(self, date):
      if self.verification_results is None:
        return None
      results = dict(self.verification_results) # make a copy
      results["CERT_TIME_VALIDITY_OK"] = self.time_validity_at_date(date)
      if self.check_crl:
        results["CERT_NOT_REVOKED"] = self.crl_validity_at_date(date)
      else:
        results["CERT_NOT_REVOKED"] = None
      return results

    def time_validity_at_date(self, date):
      """check if the time interval of validity of the certificate contains
      'date' provided as argument"""
      from_date = self.tbsCertificate.validity.get_valid_from_as_datetime()
      to_date = self.tbsCertificate.validity.get_valid_to_as_datetime()
      time_ok = to_date >= date >= from_date
      return time_ok
    
    def crl_validity_at_date(self, date):
      """check if the certificate was not on the CRL list at a particular date"""
      rev_date = self.get_revocation_date()
      if not rev_date:
        return True
      if date >= rev_date:
        return False
      else:
        return True
      
    def get_revocation_date(self):
      from certs.crl_store import CRL_cache_manager
      cache = CRL_cache_manager.get_cache()
      issuer = str(self.tbsCertificate.issuer)
      rev_date = cache.certificate_rev_date(issuer, self.tbsCertificate.serial_number)
      if not rev_date:
        return None
      rev_date = ValidityInterval.parse_date(rev_date)
      return rev_date
    
        
class Attribute():
    """
    One attribute in SignerInfo attributes set
    """
    def __init__(self, attribute):
        self.type = str(attribute.getComponentByName("type"))
        self.value = str(attribute.getComponentByName("value").getComponentByPosition(0))
        #print base64.b64encode(self.value)

class AutheticatedAttributes():
    """
    Authenticated attributes of signer info
    """
    def __init__(self, auth_attributes):
        self.attributes = []
        for aa in auth_attributes:
            self.attributes.append(Attribute(aa))

class SignerInfo():
    """
    Represents information about a signer.
    Attributes:
    - version
    - issuer 
    - serial_number (of the certificate used to verify this signature)
    - digest_algorithm 
    - encryp_algorithm
    - signature
    - auth_atributes (optional field, contains authenticated attributes)
    """
    def __init__(self, signer_info):
        self.version = signer_info.getComponentByName("version")._value
        self.issuer = Name(signer_info.getComponentByName("issuerAndSerialNum").getComponentByName("issuer"))
        self.serial_number = signer_info.getComponentByName("issuerAndSerialNum").getComponentByName("serialNumber")._value
        self.digest_algorithm = str(signer_info.getComponentByName("digestAlg"))
        self.encrypt_algorithm = str(signer_info.getComponentByName("encryptAlg"))
        self.signature = signer_info.getComponentByName("signature")._value
        auth_attrib = signer_info.getComponentByName("authAttributes")
        if auth_attrib is None:
            self.auth_attributes = None
        else:
            self.auth_attributes = AutheticatedAttributes(auth_attrib)



######
#TSTinfo
######
class MsgImprint():
    def __init__(self, asn1_msg_imprint):
        self.alg = str(asn1_msg_imprint.getComponentByName("algId"))
        self.imprint = str(asn1_msg_imprint.getComponentByName("imprint"))

class TsAccuracy():
    def __init__(self, asn1_acc):
        secs = asn1_acc.getComponentByName("seconds")
        if secs:
            self.seconds = secs._value
        milis = asn1_acc.getComponentByName("milis")
        if milis:
            self.milis = milis._value
        micros = asn1_acc.getComponentByName("micros")
        if micros:
            self.micros = micros._value

class TimeStampToken():
    '''
    Holder for Timestamp Token Info - attribute from the qtimestamp.    
    '''
    def __init__(self, asn1_tstInfo):
        self.version = asn1_tstInfo.getComponentByName("version")._value
        self.policy = str(asn1_tstInfo.getComponentByName("policy"))
        self.msgImprint = MsgImprint(asn1_tstInfo.getComponentByName("messageImprint"))
        self.serialNum = asn1_tstInfo.getComponentByName("serialNum")._value
        self.genTime = asn1_tstInfo.getComponentByName("genTime")._value
        self.accuracy = TsAccuracy(asn1_tstInfo.getComponentByName("accuracy"))
        self.tsa = Name(asn1_tstInfo.getComponentByName("tsa"))
        # place for parsed certificates in asn1 form
        self.asn1_certificates = []
        # place for certificates transformed to X509Certificate
        self.certificates = []
        #self.extensions = asn1_tstInfo.getComponentByName("extensions")
    
    def certificates_contain(self, cert_serial_num):
        """
        Checks if set of certificates of this timestamp contains
        certificate with specified serial number.
        Returns True if it does, False otherwise.
        """
        for cert in self.certificates:
          if cert.tbsCertificate.serial_number == cert_serial_num:
            return True
        return False
    
    def get_genTime_as_datetime(self):
      """
      parses the genTime string and returns a datetime object;
      it also adjusts the time according to local timezone, so that it is
      compatible with other parts of the library
      """
      year = int(self.genTime[:4])
      month = int(self.genTime[4:6])
      day = int(self.genTime[6:8])
      hour = int(self.genTime[8:10])
      minute = int(self.genTime[10:12])
      second = int(self.genTime[12:14])
      rest = self.genTime[14:].strip("Z")
      if rest:
        micro = int(float(rest)*1e6)
      else:
        micro = 0
      tz_delta = datetime.timedelta(seconds=time.daylight and time.altzone
                                    or time.timezone)
      return datetime.datetime(year, month, day, hour, minute, second, micro) - tz_delta
