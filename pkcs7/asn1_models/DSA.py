
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

from pyasn1.type import namedtype,univ

# 7.3.3  DSA Signature Keys
#
#Dss-Parms  ::=  SEQUENCE  {
#    p             INTEGER,
#    q             INTEGER,
#    g             INTEGER  }

class DsaPubKey(univ.Integer):
	pass

class DssParams(univ.Sequence):
    componentType = namedtype.NamedTypes(
                                         namedtype.NamedType("p", univ.Integer()),
                                         namedtype.NamedType("q", univ.Integer()),
                                         namedtype.NamedType("g", univ.Integer()),
                                         )
