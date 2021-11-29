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

import secrets
import random

import ShamirSecretSharing as SSS
import BCH

def generate_random_share(ind, k, ident=""):
    secret = secrets.token_bytes(32)
    secret_5 = BCH.convertbits(secret, 8, 5)
    if not ident:
        ident = BCH.charset_encode([0,0,0,0])
    chk = BCH.create_checksum(BCH.MS32_CHECKSUM, secret_5)
    data = secret_5 + chk
    if not ident:
        ident = BCH.charset_encode([0,0,0,0])
    return SSS.SecretShare(BCH.MS32_CHECKSUM, k, ident, ind, data)

def generate_secret(ident="", k=0):
    return generate_random_share("s", k, ident)

def main():
    # Verify the GF32_LOG and _EXP tables are correct
    BCH.verify_GF32_tables()

    k = 2
    n = 31
    print("Threshold set to {}.".format(k))

    # Generate a master secret
    master_secret = generate_secret("test", k)
    print("Using master secret: {}".format(master_secret.to_string()))

    # Generate k-1 random shares
    random_shares = []
    for i in range(0, k-1):
        share_i = generate_random_share(i, k, "test")
        random_shares.append(share_i)
        print("Using random starting share {}: {}".format(i, share_i.to_string()))

    print("Generating {} more shares.".format(n-k+1))
    derive_indices = [x+1 if x >= 16 else x for x in range(k-1, n)]
    derived_shares = SSS.reconstruct_shares([master_secret] + random_shares, derive_indices)
    for s in derived_shares:
        print("Derived share {}: {}. Checksum valid: {}.".format(s.index, s.to_string(), BCH.verify_checksum(BCH.MS32_CHECKSUM, s.data)))

    print("Creation of {}-of-{} shamir secret scheme complete.".format(k, n))

    all_shares = random_shares + derived_shares

    selection = random.sample(all_shares, 3)
    print("Selected shares with indices {}".format([s.index for s in selection]))

    reconstructed_master = SSS.reconstruct_shares(selection)[0]
    print("Reconstructed master: {}".format(reconstructed_master.to_string()))

    print("Master matches original:", master_secret.to_string() == reconstructed_master.to_string())

if __name__ == "__main__":
    main()
