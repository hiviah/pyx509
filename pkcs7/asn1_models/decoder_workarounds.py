from pyasn1.type import univ
from pyasn1.codec.ber import decoder as berDecoder
from pyasn1.codec.der import decoder as derDecoder

# Clone stock DER decoder and replace its boolean handler so that it permits
# BER encoding of boolean (i.e. 0 => False, anything else => True).
# According to spec, CER/DER should only accept 0 as False and 0xFF as True.
# Though some authors of X.509-cert-creating software didn't get the memo.

class BooleanFixDerDecoder(derDecoder.Decoder): pass

# This is a tag->decoder map. We take DER map and replace its Boolean handler
# with stock BER one. That will make the decoder tolerant to BER-encoded
# Booleans in DER substrate.
booleanFixTagMap = derDecoder.tagMap.copy()
booleanFixTagMap[univ.Boolean.tagSet] = berDecoder.BooleanDecoder()

# Instantiate our modified DER decoder
decode = BooleanFixDerDecoder(booleanFixTagMap, derDecoder.typeMap)
