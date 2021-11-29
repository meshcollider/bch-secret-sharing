# Copyright (c) 2021 Samuel Dobson
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

import BCH

class SecretShare:
    def __init__(self, ct, k, identifier, index, data):
        if k != 0 and (k < 2 or k > 9):
            raise ValueError("Threshold parameter must be between 2 and 9, or 0.")

        if k == 0 and index != "s":
            raise ValueError("Share index must be 's' when k = 0.")

        self.k = k
        self.index = index

        if len(identifier) != 4:
            raise ValueError("Identifier must have length four.")

        self.identifier = identifier

        if not BCH.verify_checksum(ct, data):
            raise ValueError("Checksum on share does not verify correctly.")

        self.ctype = ct
        self.data = data

    def to_string(self):
        ind = "s" if self.index == "s" else BCH.charset_encode([self.index])
        return "ms1" + str(self.k) + self.identifier + ind + BCH.charset_encode(self.data)


def gf32_lagrange_interpolation(x, points):
    """construct the lagrange interpolation of points and evaluate at x, in GF(32)"""
    res = 0
    for i, (x_i, y_i) in enumerate(points):
        # evaluate lagrange basis polynomial l_i at x
        # l_i(x) = product of (x - x_j) / (x_i - x_j) for j != i

        # the entire term will be 0 if x == x_i is
        if y_i == 0:
            continue

        log_lix = 0
        for j, (x_j, y_j) in enumerate(points):
            if i == j: continue
            # in characteristic 2, addition and subtraction are both XOR
            log_lix += BCH.GF32_LOG[( x ^ x_j )] + 31
            log_lix -= BCH.GF32_LOG[( x_i ^ x_j )]
            log_lix %= 31

        # Now multiply l_i(x) by y_i and add to result
        log_lix += BCH.GF32_LOG[y_i]
        ylix = BCH.GF32_EXP[log_lix % 31]
        res ^= ylix
    return res

def reconstruct_shares(shares, inds=[16]):
    """Given a list of shares, reconstruct a set of specific shares using lagrange interpolation"""

    if len(shares) < 1:
        raise ValueError("Shares list cannot be empty.")

    k = shares[0].k
    ctype = shares[0].ctype

    if len(shares) < k:
        raise ValueError("Require at least {} shares to reconstruct secret, only {} given.".format(k, len(shares)))

    data_len = len(shares[0].data)
    ident = shares[0].identifier

    points = [[] for _ in range(data_len)]

    for s in shares:
        if s.identifier != ident:
            raise ValueError("Shares must all have the same identifier. {} != {}".format(s.identifier, ident))
        if len(s.data) != data_len:
            raise ValueError("Shares must all have the same data length. {} != {}.".format(len(s.data), data_len))

        index = 16 if s.index == "s" else s.index
        if index in inds:
            raise ValueError("Requested index {} already provided in shares list.".format(index))

        for i,c in enumerate(s.data):
            point = (index, c)
            points[i].append(point)

    constructed_shares = []
    for x in inds:
        new_share_data = []
        for ps in points:
            # Interpolate the points for this character index
            y = gf32_lagrange_interpolation(x, ps)
            new_share_data.append(y)
        new_share_index = "s" if x == 16 else x
        new_share = SecretShare(ctype, k, ident, new_share_index, new_share_data)
        constructed_shares.append(new_share)
    return constructed_shares
