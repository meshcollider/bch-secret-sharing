# Copyright (c) 2021 Samuel Dobson
# Copyright (c) 2017, 2020 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

GF32_EXP = [1, 2, 4, 8, 16, 9, 18, 13, 26, 29, 19, 15, 30, 21, 3, 6, 12, 24, 25, 27, 31, 23, 7, 14, 28, 17, 11, 22, 5, 10, 20, 1]
GF32_LOG = [-1, 31, 1, 14, 2, 28, 15, 22, 3, 5, 29, 26, 16, 7, 23, 11, 4, 25, 6, 10, 30, 13, 27, 21, 17, 18, 8, 19, 24, 9, 12, 20]

# 41 encodes the defining polynomial of the extension GF(32) over GF(2)
GF32_EXT_MOD = 41

BECH32M_CONST = 0x2bc830a3
BECH32_GENS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

MS32_CONST = 0x10ce0795c2fd1e62a
MS32_GENS = [0x1f28f80fffe92f842, 0x1751a20bdef255484, 0x07a316039ceda0d08, 0x0e0e2c0739da09a10, 0x1c164a0e739d13129]
MS32_CHECKSUM_RESIDUE = 0x23181b3

class ChecksumType:
    CHECKSUM_CONST = 1
    LENGTH = 0
    GENS = []
    CHECKSUM_RESIDUE = 1
    def __init__(self, c, l, gs, cr=1):
        self.CHECKSUM_CONST = c
        self.LENGTH = l
        self.GENS = gs
        self.CHECKSUM_RESIDUE = cr

BECH32M_CHECKSUM = ChecksumType(BECH32M_CONST, 6, BECH32_GENS)
MS32_CHECKSUM = ChecksumType(MS32_CONST, 13, MS32_GENS, MS32_CHECKSUM_RESIDUE)

def polymod(ctype, values):
    """Internal function that computes the Bech32 checksum."""
    chk = ctype.CHECKSUM_RESIDUE
    for value in values:
        bitlength = (ctype.LENGTH - 1) * 5
        top = chk >> bitlength
        mask = 2**bitlength - 1
        chk = (chk & mask) << 5 ^ value
        for i in range(5):
            chk ^= ctype.GENS[i] if ((top >> i) & 1) else 0
    return chk

def create_checksum(ctype, values):
    """Compute the checksum values given values without a checksum."""
    pm = polymod(ctype, values + [0] * ctype.LENGTH) ^ ctype.CHECKSUM_CONST
    return [(pm >> 5 * (ctype.LENGTH - 1 - i)) & 31 for i in range(ctype.LENGTH)]

def verify_checksum(ctype, data):
    return polymod(ctype, data) == ctype.CHECKSUM_CONST

def charset_encode(data):
    """Encode data in the bech32 characterset."""
    res = []
    for d in data:
        if d < 0 or d > len(CHARSET):
            raise ValueError("Invalid data for bech32 encoding: {}".format(data))
        res += CHARSET[d]
    return ''.join(res)

def charset_decode(enc):
    """Decode data from the bech32 characterset."""
    res = []
    for x in enc:
        val = CHARSET.find(x)
        if val == -1:
            raise ValueError("Not a valid bech32 encoded string: {}".format(enc))
        res += val
    return res

def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def verify_GF32_tables():
    """Helper function for testing, verifies the GF32_LOG and _EXP tables are correct."""
    v = 1
    for i in range(1, 32):
        v = v << 1
        if (v & 32):
            v ^= GF32_EXT_MOD
        if GF32_LOG[v] != i:
            print("ERROR: Expected LOG of {} to be {}, got {}.".format(v, i, GF32_LOG[v]))
        if GF32_EXP[i] != v:
            print("ERROR: Expected EXP of {} to be {}, got {}.".format(i, v, GF32_EXP[i]))
    print("GF32 table verification complete!\n")