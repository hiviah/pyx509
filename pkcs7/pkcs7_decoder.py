
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
Decoding of PKCS7 messages
'''

from cStringIO import StringIO

# dslib imports
from pkcs7.asn1_models.decoder_workarounds import decode
from pyasn1 import error

# local imports
from asn1_models.pkcs_signed_data import *
from asn1_models.digest_info import *
from asn1_models.TST_info import *


class StringView(object):
  
  def __init__(self, string, start, end):
    self._string = string
    self._start = start
    if end == None:
      self._end = len(string)
    else:
      self._end = end 

  def __len__(self):
    return self._end - self._start
  
  def __getitem__(self, key):
    if type(key) == int:
      if key < 0:
        self._string.seek(self._end+key)
        return self._string.read(1)
      else:
        if key >= (self._end - self._start):
          raise IndexError()
        self._string.seek(self._start+key)
        return self._string.read(1)
    elif type(key) == slice:
      if key.stop == None:
        end = self._end
      elif key.stop < 0:
        end = self._end+key.stop
      else:
        end = self._start+key.stop
      start = self._start+(key.start or 0)
      return StringView(self._string, start=start, end=end)
    else:
      raise IndexError()

  def __str__(self):
    self._string.seek(self._start)
    return self._string.read(self._end-self._start)

  def __nonzero__(self):
    return len(self)


def decode_msg(message):    
    '''
    Decodes message in DER encoding.
    Returns ASN1 message object
    '''
    # create template for decoder
    msg = Message()
    # decode pkcs signed message
    mess_obj = StringIO(message)
    mess_view = StringView(mess_obj, 0, len(message))
    decoded = decode(mess_view, asn1Spec=msg)
    message = decoded[0]
    return message


def decode_qts(qts_bytes):
    '''
    Decodes qualified timestamp
    '''
    qts = Qts()    
    decoded = decode(qts_bytes,asn1Spec=qts)
    qts = decoded[0]
    
    return qts


def decode_tst(tst_bytes):
    '''
    Decodes Timestamp Token
    '''
    tst = TSTInfo()
    decoded = decode(tst_bytes,asn1Spec=tst)
    tst = decoded[0]
    
    return tst



    
    
    
 
