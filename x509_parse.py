import sys
from binascii import hexlify

from pkcs7.asn1_models.X509_certificate import Certificate
from pkcs7_models import X509Certificate, PublicKeyInfo, ExtendedKeyUsageExt

from pyasn1.codec.der import decoder

def x509_parse(derData):
	"""Decodes certificate.
	@param derData: DER-encoded certificate string
	@returns: pkcs7_models.X509Certificate
	"""
	cert = decoder.decode(derData, asn1Spec=Certificate())[0]
	x509cert = X509Certificate(cert)
	return x509cert

#Sample usage showing retrieving certificate fields
if __name__ == "__main__":
	if len(sys.argv) < 2:
		prints >> sys.stderr, "Usage: x509_parse.py certificate.der"
		sys.exit(1)
	
	der_file = sys.argv[1]
		
	x509cert = x509_parse(file(der_file).read())
	tbs = x509cert.tbsCertificate
	
	print "X.509 version: %d (0x%x)" % (tbs.version + 1, tbs.version)
	print "Serial no: 0x%x" % tbs.serial_number
	print "Signature algorithm:", x509cert.signature_algorithm
	print "Issuer:", str(tbs.issuer)
	print "Validity:"
	print "\tNot Before:", tbs.validity.get_valid_from_as_datetime()
	print "\tNot After:", tbs.validity.get_valid_to_as_datetime()
	print "Subject:", str(tbs.subject)
	print "Subject Public Key Info:"
	print "\tPublic Key Algorithm:", tbs.pub_key_info.algName
	
	if tbs.issuer_uid:
		print "Issuer UID:", hexlify(tbs.issuer_uid)
	if tbs.subject_uid:
		print "Subject UID:", hexlify(tbs.subject_uid)
	
	algType = tbs.pub_key_info.algType
	algParams = tbs.pub_key_info.key
	
	if (algType == PublicKeyInfo.RSA):
		print "\t\tModulus:", hexlify(algParams["mod"])
		print "\t\tExponent:", algParams["exp"]
	elif (algType == PublicKeyInfo.DSA):
		print "\t\tPub:", hexlify(algParams["pub"]),
		print "\t\tP:", hexlify(algParams["p"]),
		print "\t\tQ:", hexlify(algParams["q"]),
		print "\t\tG:", hexlify(algParams["g"]),
	else:
		print "\t\t(parsing keys of this type not implemented)"
	
	print "\nExtensions:"
	if tbs.authInfoAccessExt:
		print "\tAuthority Information Access Ext: is_critical:", tbs.authInfoAccessExt.is_critical
		for aia in tbs.authInfoAccessExt.value:
			print "\t\taccessLocation:", aia.access_location
			print "\t\taccessMethod:", aia.access_method
			print "\t\toid:", aia.id
	if tbs.authKeyIdExt:
		print "\tAuthority Key Id Ext: is_critical:", tbs.authKeyIdExt.is_critical
		aki = tbs.authKeyIdExt.value
		if hasattr(aki, "key_id"):
			print "\t\tkey id", hexlify(aki.key_id)
		if hasattr(aki, "auth_cert_sn"):
			print "\t\tcert serial no", aki.auth_cert_sn
		if hasattr(aki, "auth_cert_issuer"):
			print "\t\tissuer", aki.auth_cert_issuer
			
	if tbs.basicConstraintsExt:
		print "\tBasic Constraints Ext: is_critical:", tbs.basicConstraintsExt.is_critical
		bc = tbs.basicConstraintsExt.value
		print "\t\tCA:", bc.ca
		print "\t\tmax_path_len:", bc.max_path_len
	
	if tbs.certPoliciesExt:
		print "\tCert Policies Ext: is_critical:", tbs.certPoliciesExt.is_critical
		policies = tbs.certPoliciesExt.value
		for policy in policies:
			print "\t\tpolicy OID:", policy.id
			for qualifier in policy.qualifiers:
				print "\t\t\toid:", qualifier.id
				print "\t\t\tqualifier:", qualifier.qualifier
		
	if tbs.crlDistPointsExt:
		print "\tCRL Distribution Points: is_critical:", tbs.crlDistPointsExt.is_critical
		crls = tbs.crlDistPointsExt.value
		for crl in crls:
			if crl.dist_point:
				print "\t\tdistribution point:", crl.dist_point
			if crl.issuer:
				print "\t\tissuer:", crl.issuer
			if crl.reasons:
				print "\t\treasons:", crl.reasons
	
	if tbs.extKeyUsageExt:
		print "\tExtended Key Usage: is_critical:", tbs.extKeyUsageExt.is_critical
		eku = tbs.extKeyUsageExt.value
		set_flags = [flag for flag in ExtendedKeyUsageExt._keyPurposeAttrs.values() if getattr(eku, flag)]
		print "\t\t", ",".join(set_flags)
			
	if tbs.keyUsageExt:
		print "\tKey Usage: is_critical:", tbs.keyUsageExt.is_critical
		ku = tbs.keyUsageExt.value
		flags = ["digitalSignature","nonRepudiation", "keyEncipherment",
			 "dataEncipherment", "keyAgreement", "keyCertSign",
			 "cRLSign", "encipherOnly", "decipherOnly",
			]
		
		set_flags = [flag for flag in flags if getattr(ku, flag)]
		print "\t\t", ",".join(set_flags)
	
	if tbs.policyConstraintsExt:
		print "\tPolicy Constraints: is_critical:", tbs.policyConstraintsExt.is_critical
		pc = tbs.policyConstraintsExt.value
		
		print "\t\trequire explicit policy: ", pc.requireExplicitPolicy
		print "\t\tinhibit policy mapping: ", pc.inhibitPolicyMapping
	
	#if tbs.netscapeCertTypeExt: #...partially implemented
	
	if tbs.subjAltNameExt:
		print "\tSubject Alternative Name: is_critical:", tbs.subjAltNameExt.is_critical
		san = tbs.subjAltNameExt.value
		print "\t\tDNS names:", ",".join(san.names) #only DNS names supported now
		
	if tbs.subjKeyIdExt:
		print "\tSubject Key Id: is_critical:", tbs.subjKeyIdExt.is_critical
		ski = tbs.subjKeyIdExt.value
		print "\t\tkey id", hexlify(ski.subject_key_id)

	print "Signature:", hexlify(x509cert.signature)
		
