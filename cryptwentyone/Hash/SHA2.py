# cryptwentyone.Hash.SHA2.py
# CodeWriter21

from .Hash import Hash

__all__ = ['SHA2Python', 'SHA256Python']

# Constant values for SHA-2.
H0 = 0x6a09e667
H1 = 0xbb67ae85
H2 = 0x3c6ef372
H3 = 0xa54ff53a
H4 = 0x510e527f
H5 = 0x9b05688c
H6 = 0x1f83d9ab
H7 = 0x5be0cd19

k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]


class SHA2Python(Hash):
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
        self.h0 = H0
        self.h1 = H1
        self.h2 = H2
        self.h3 = H3
        self.h4 = H4
        self.h5 = H5
        self.h6 = H6
        self.h7 = H7

    def _hash(self) -> bytes:
        """
        Calculates the SHA2 hash of the message.

        :return: The SHA2 hash of the message.
        """
        # Pad the message with a 1 bit followed by 0 bits.
        message = self.message + b"\x80"  # 0b10000000

        # Pad the message with 0 bits until its length is a multiple of 512 bits.
        message += b"\x00" * (64 - (len(message) + 8) % 64)

        # Append a 64-bit representation of the original message's length
        message += self.ml.to_bytes(8, 'big')

        # Process the padded message in successive 512-bit chunks.
        for i in range(0, len(message), 64):
            self._process_chunk(message[i:i + 64])

        # Return the result as bytes
        return self.h0.to_bytes(4, 'big') + self.h1.to_bytes(4, 'big') + self.h2.to_bytes(4, 'big') + \
               self.h3.to_bytes(4, 'big') + self.h4.to_bytes(4, 'big') + self.h5.to_bytes(4, 'big') + \
               self.h6.to_bytes(4, 'big') + self.h7.to_bytes(4, 'big')

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
            ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
            temp1 = self.modular_add(h + s1 + ch + k[i] + w[i])
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


SHA256Python = SHA2Python
