# cryptwentyone.Hash.SHA2.py
# CodeWriter21
from abc import ABC

from .Hash import Hash

__all__ = ['SHA256Python', 'SHA224Python', 'SHA384Python', 'SHA512Python']


class _SHA2Python(Hash, ABC):
    k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    H0 = H1 = H2 = H3 = H4 = H5 = H6 = H7 = 0

    h0: int
    h1: int
    h2: int
    h3: int
    h4: int
    h5: int
    h6: int
    h7: int
    name: str = 'sha2'

    def _initialize_variables(self):
        self.h0 = self.H0
        self.h1 = self.H1
        self.h2 = self.H2
        self.h3 = self.H3
        self.h4 = self.H4
        self.h5 = self.H5
        self.h6 = self.H6
        self.h7 = self.H7

    def _preprocess(self):
        """
        Pads the message and adds the representation of length to it.

        :return:
        """
        # Pad the message with a 1 bit followed by 0 bits.
        message = self.message + b"\x80"  # 0b10000000

        # Pad the message with 0 bits until its length is a multiple of 512 bits.
        message += b"\x00" * (64 - (len(message) + 8) % 64)

        # Append a 64-bit representation of the original message's length
        message += self.ml.to_bytes(8, 'big')

        return message

    def _process_chunk(self, chunk: bytes):
        """
        Processes a 512-bit chunk of the message.

        :param chunk: The 512-bit chunk of the message.
        """
        # Break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15.
        w = [0] * 64
        for j in range(16):
            w[j] = int.from_bytes(chunk[j * 4:j * 4 + 4], byteorder="big")

        # Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for i in range(16, 64):
            s0 = self.right_rotate(w[i - 15], 7) ^ self.right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = self.right_rotate(w[i - 2], 17) ^ self.right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = self.modular_add(w[i - 16] + s0 + w[i - 7] + s1)

        # Initialize hash value for this chunk.
        a = self.h0
        b = self.h1
        c = self.h2
        d = self.h3
        e = self.h4
        f = self.h5
        g = self.h6
        h = self.h7

        # Main loop.
        for i in range(64):
            s1 = self.right_rotate(e, 6) ^ self.right_rotate(e, 11) ^ self.right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = self.modular_add(h + s1 + ch + self.k[i] + w[i])
            s0 = self.right_rotate(a, 2) ^ self.right_rotate(a, 13) ^ self.right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = self.modular_add(s0, maj)
            h = g
            g = f
            f = e
            e = self.modular_add(d, temp1)
            d = c
            c = b
            b = a
            a = self.modular_add(temp1, temp2)

        # Add this chunk's hash to result so far.
        self.h0 = self.modular_add(self.h0, a)
        self.h1 = self.modular_add(self.h1, b)
        self.h2 = self.modular_add(self.h2, c)
        self.h3 = self.modular_add(self.h3, d)
        self.h4 = self.modular_add(self.h4, e)
        self.h5 = self.modular_add(self.h5, f)
        self.h6 = self.modular_add(self.h6, g)
        self.h7 = self.modular_add(self.h7, h)

    def __repr__(self):
        return f"SHA2Python(message={self.message!r}, hash={str(self)!r})"


class SHA224Python(_SHA2Python):
    # Constant values for SHA-224
    H0 = 0xc1059ed8
    H1 = 0x367cd507
    H2 = 0x3070dd17
    H3 = 0xf70e5939
    H4 = 0xffc00b31
    H5 = 0x68581511
    H6 = 0x64f98fa7
    H7 = 0xbefa4fa4

    name: str = 'sha224'

    def _hash(self) -> bytes:
        """
        Calculates the SHA224 hash of the message.

        :return: The SHA224 hash of the message.
        """
        message = self._preprocess()

        # Process the preprocessed message in successive 512-bit chunks.
        for i in range(0, len(message), 64):
            self._process_chunk(message[i:i + 64])

        # Return the result as bytes
        return self.h0.to_bytes(4, 'big') + self.h1.to_bytes(4, 'big') + self.h2.to_bytes(4, 'big') + \
               self.h3.to_bytes(4, 'big') + self.h4.to_bytes(4, 'big') + self.h5.to_bytes(4, 'big') + \
               self.h6.to_bytes(4, 'big')

    def __repr__(self):
        return f"SHA256Python(message={self.message!r}, hash={str(self)!r})"


class SHA256Python(_SHA2Python):
    # Constant values for SHA-256
    H0 = 0x6a09e667
    H1 = 0xbb67ae85
    H2 = 0x3c6ef372
    H3 = 0xa54ff53a
    H4 = 0x510e527f
    H5 = 0x9b05688c
    H6 = 0x1f83d9ab
    H7 = 0x5be0cd19

    name: str = 'sha256'

    def _hash(self) -> bytes:
        """
        Calculates the SHA256 hash of the message.

        :return: The SHA256 hash of the message.
        """
        message = self._preprocess()

        # Process the preprocessed message in successive 512-bit chunks.
        for i in range(0, len(message), 64):
            self._process_chunk(message[i:i + 64])

        # Return the result as bytes
        return self.h0.to_bytes(4, 'big') + self.h1.to_bytes(4, 'big') + self.h2.to_bytes(4, 'big') + \
               self.h3.to_bytes(4, 'big') + self.h4.to_bytes(4, 'big') + self.h5.to_bytes(4, 'big') + \
               self.h6.to_bytes(4, 'big') + self.h7.to_bytes(4, 'big')

    def __repr__(self):
        return f"SHA256Python(message={self.message!r}, hash={str(self)!r})"


class _SHA2Python64(_SHA2Python, ABC):
    k = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
         0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
         0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
         0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
         0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
         0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
         0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
         0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
         0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
         0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
         0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
         0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
         0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
         0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
         0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
         0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]

    X = 0x10000000000000000  # 2**64
    default_n_bits: int = 64

    def _preprocess(self):
        """
        Pads the message and adds the representation of length to it.

        :return:
        """
        # Pad the message with a 1 bit followed by 0 bits.
        message = self.message + b"\x80"  # 0b10000000

        # Pad the message with 0 bits until its length is a multiple of 512 bits.
        message += b"\x00" * (128 - (len(message) + 16) % 128)

        # Append a 128-bit representation of the original message's length
        message += self.ml.to_bytes(16, 'big')

        return message

    def _process_chunk(self, chunk: bytes):
        """
        Processes a 1024-bit chunk of the message.

        :param chunk: The 1024-bit chunk of the message.
        """
        # Break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15.
        w = [0] * 80
        for j in range(16):
            w[j] = int.from_bytes(chunk[j * 8:j * 8 + 8], byteorder="big")

        # Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for i in range(16, 80):
            s0 = self.right_rotate(w[i - 15], 1) ^ self.right_rotate(w[i - 15], 8) ^ (w[i - 15] >> 7)
            s1 = self.right_rotate(w[i - 2], 19) ^ self.right_rotate(w[i - 2], 61) ^ (w[i - 2] >> 6)
            w[i] = self.modular_add(w[i - 16] + s0 + w[i - 7] + s1)

        # Initialize hash value for this chunk.
        a = self.h0
        b = self.h1
        c = self.h2
        d = self.h3
        e = self.h4
        f = self.h5
        g = self.h6
        h = self.h7

        # Main loop.
        for i in range(80):
            s1 = self.right_rotate(e, 14) ^ self.right_rotate(e, 18) ^ self.right_rotate(e, 41)
            ch = (e & f) ^ (~e & g)
            temp1 = self.modular_add(h + s1 + ch + self.k[i] + w[i])
            s0 = self.right_rotate(a, 28) ^ self.right_rotate(a, 34) ^ self.right_rotate(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = self.modular_add(s0, maj)
            h = g
            g = f
            f = e
            e = self.modular_add(d, temp1)
            d = c
            c = b
            b = a
            a = self.modular_add(temp1, temp2)

        # Add this chunk's hash to result so far.
        self.h0 = self.modular_add(self.h0, a)
        self.h1 = self.modular_add(self.h1, b)
        self.h2 = self.modular_add(self.h2, c)
        self.h3 = self.modular_add(self.h3, d)
        self.h4 = self.modular_add(self.h4, e)
        self.h5 = self.modular_add(self.h5, f)
        self.h6 = self.modular_add(self.h6, g)
        self.h7 = self.modular_add(self.h7, h)


class SHA384Python(_SHA2Python64):
    # Constant values for SHA-384
    H0 = 0xcbbb9d5dc1059ed8
    H1 = 0x629a292a367cd507
    H2 = 0x9159015a3070dd17
    H3 = 0x152fecd8f70e5939
    H4 = 0x67332667ffc00b31
    H5 = 0x8eb44a8768581511
    H6 = 0xdb0c2e0d64f98fa7
    H7 = 0x47b5481dbefa4fa4

    name: str = 'sha384'

    def _hash(self) -> bytes:
        """
        Calculates the SHA384 hash of the message.

        :return: The SHA384 hash of the message.
        """
        message = self._preprocess()

        # Process the preprocessed message in successive 512-bit chunks.
        for i in range(0, len(message), 128):
            self._process_chunk(message[i:i + 128])

        # Return the result as bytes
        return self.h0.to_bytes(8, 'big') + self.h1.to_bytes(8, 'big') + self.h2.to_bytes(8, 'big') + \
               self.h3.to_bytes(8, 'big') + self.h4.to_bytes(8, 'big') + self.h5.to_bytes(8, 'big')

    def __repr__(self):
        return f"SHA384Python(message={self.message!r}, hash={str(self)!r})"


class SHA512Python(_SHA2Python64):
    # Constant values for SHA-512
    H0 = 0x6a09e667f3bcc908
    H1 = 0xbb67ae8584caa73b
    H2 = 0x3c6ef372fe94f82b
    H3 = 0xa54ff53a5f1d36f1
    H4 = 0x510e527fade682d1
    H5 = 0x9b05688c2b3e6c1f
    H6 = 0x1f83d9abfb41bd6b
    H7 = 0x5be0cd19137e2179

    name: str = 'sha512'

    def _hash(self) -> bytes:
        """
        Calculates the SHA512 hash of the message.

        :return: The SHA512 hash of the message.
        """
        message = self._preprocess()

        # Process the preprocessed message in successive 512-bit chunks.
        for i in range(0, len(message), 128):
            self._process_chunk(message[i:i + 128])

        # Return the result as bytes
        return self.h0.to_bytes(8, 'big') + self.h1.to_bytes(8, 'big') + self.h2.to_bytes(8, 'big') + \
               self.h3.to_bytes(8, 'big') + self.h4.to_bytes(8, 'big') + self.h5.to_bytes(8, 'big') + \
               self.h6.to_bytes(8, 'big') + self.h7.to_bytes(8, 'big')

    def __repr__(self):
        return f"SHA512Python(message={self.message!r}, hash={str(self)!r})"
