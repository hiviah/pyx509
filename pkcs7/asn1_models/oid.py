
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
Map of OIDs and their names
'''
oid_map = {
       "1.3.14.3.2.26" : "SHA-1",
       "2.16.840.1.101.3.4.2.1" : "SHA-256",
       "2.16.840.1.101.3.4.2.2" : "SHA-384",
       "2.16.840.1.101.3.4.2.3" : "SHA-512",
       "1.2.840.113549.1.7.1" : "data",
       "1.2.840.113549.1.7.2" : "signedData",
       "1.2.840.113549.1.1.5" : "SHA1/RSA",
       "1.2.840.113549.1.1.1" : "RSA",
       "1.2.840.113549.1.1.11" : "SHA256/RSA",
       "1.2.840.10040.4.1" : "DSA",
       "1.2.840.10040.4.3" : "SHA1/DSA",
       
       "2.5.4.6" : "id-at-countryName",
       "2.5.4.10" : "id-at-organizationName ",
       "2.5.4.3" : "id-at-commonName",
       "2.5.4.11" : "id-at-organizationalUnitName",       
       
       "2.5.29.17" : "id-ce-subjectAltName",
       "2.5.29.19" : "basicConstraints",
       "2.5.29.32" : "Certificate policies",
       "1.3.6.1.5.5.7.1.3" : "id-pe-qcStatements",
       "2.5.29.15" : "id-ce-keyUsage",
       "2.5.29.14" : "id-ce-subjectKeyIdentifier ",
       "2.5.29.31" : "id-ce-CRLDistributionPoints ",
       "2.5.29.35" : "id-ce-authorityKeyIdentifier ",
       
       "2.5.29.20" : "CRL Number",
       "2.5.29.21" : "Reason Code",
       "2.5.29.24" : "Invalidity Data",
       
       
       "1.2.840.113549.1.9.3" : "contentType",
       "1.2.840.113549.1.9.4" : "messageDigest",
       "1.2.840.113549.1.9.5" : "Signing Time"       
       }
