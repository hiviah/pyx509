
from pkcs7.asn1_models.X509_certificate import Certificate
from pkcs7_models import X509Certificate

from pyasn1.codec.der import decoder, encoder
import string, base64
import binascii

stSpam, stHam, stDump = 0, 1, 2

def readPemFromFile(fileObj):
    state = stSpam
    while 1:
        certLine = fileObj.readline()
        if not certLine:
            break
        certLine = string.strip(certLine)
        if state == stSpam:
            if certLine == '-----BEGIN CERTIFICATE-----':
                certLines = []
                state = stHam
                continue
        if state == stHam:
            if certLine == '-----END CERTIFICATE-----':
                state = stDump
            else:
                certLines.append(certLine)
        if state == stDump:
            substrate = ''
            for certLine in certLines:
                substrate = substrate + base64.decodestring(certLine)
            return substrate

# Read ASN.1/PEM X.509 certificates on stdin, parse each into plain text,
# then build substrate from it
if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print "Usage: x509_dump.py certificate.pem"
        sys.exit(-1)
    
    certType = Certificate()

    certCnt = 0

    infile = file(sys.argv[1])
    while 1:
        substrate = readPemFromFile(infile)
        if not substrate:
            break
        
        cert = decoder.decode(substrate, asn1Spec=certType)[0]
        x509cert = X509Certificate(cert)
        issuer = x509cert.tbsCertificate.issuer.get_attributes()
        #print cert.prettyPrint()
        print "Issuer organization", issuer.get("2.5.4.10")
        
        
        assert encoder.encode(cert) == substrate, 'cert recode fails'
        
        certCnt = certCnt + 1

    print '*** %s PEM cert(s) de/serialized' % certCnt

