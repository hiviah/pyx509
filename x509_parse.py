
from pkcs7.asn1_models.X509_certificate import Certificate
from pkcs7_models import X509Certificate

from pyasn1.codec.der import decoder

def x509_parse(derData):
	"""Decodes certificate.
	@param derData: DER-encoded certificate string
	@returns: pkcs7_models.X509Certificate
	"""
	cert = decoder.decode(derData, asn1Spec=Certificate())[0]
	x509cert = X509Certificate(cert)
	return x509cert

