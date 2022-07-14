# cryptwentyone.Hash.SHA1.py
# CodeWriter21

from .Hash import Hash

__all__ = ['SHA1Python']

# Constant values for SHA-1.
H0 = 0x67452301
H1 = 0xEFCDAB89
H2 = 0x98BADCFE
H3 = 0x10325476
H4 = 0xC3D2E1F0


class SHA1Python(Hash):
    h0: int
    h1: int
    h2: int
    h3: int
    h4: int
    name: str = 'sha1'

    def _initialize_variables(self):
        self.h0: int = H0
        self.h1: int = H1
        self.h2: int = H2
        self.h3: int = H3
        self.h4: int = H4

    def _hash(self) -> bytes:
        """
        Calculates the SHA1 hash of the message.

        :return: The SHA1 hash of the message.
        """
        # Pad the message with a 1 bit followed by 0 bits.
        message = self.message + b"\x80"  # 0b10000000

        # Pad the message with 0 bits until its length is a multiple of 512 bits.
        message += b"\x00" * (63 - (len(message) + 8) % 64)

        # Append a 64-bit representation of the original message's length
        message += self.ml.to_bytes(8, 'big')

        # Process the padded message in successive 512-bit chunks.
        for i in range(0, len(message), 64):
            self._process_chunk(message[i:i + 64])

        # Return the result as bytes
        return self.h0.to_bytes(4, 'big') + self.h1.to_bytes(4, 'big') + self.h2.to_bytes(4, 'big') + self.h3.to_bytes(
            4, 'big') + self.h4.to_bytes(4, 'big')

    def _process_chunk(self, chunk: bytes):
        """
        Processes a 512-bit chunk of the message.

        :param chunk: The 512-bit chunk of the message.
        """
        # Break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15.
        w = [0] * 80
        for j in range(16):
            w[j] = int.from_bytes(chunk[j * 4:j * 4 + 4], byteorder="big")

        # Message schedule: extend the sixteen 32-bit words into eighty 32-bit words:
        for i in range(16, 80):
            # Note: SHA-0 differs by not having this left-rotate.
            w[i] = self.left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

        # Initialize hash value for this chunk.
        a = self.h0
        b = self.h1
        c = self.h2
        d = self.h3
        e = self.h4

        # Main loop.
        for i in range(80):
            if 0 <= i <= 19:
                temp = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                temp = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                temp = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                temp = b ^ c ^ d
                k = 0xCA62C1D6
            temp = self.modular_add(self.left_rotate(a, 5), temp, e, k, w[i])
            e = d
            d = c
            c = self.left_rotate(b, 30)
            b = a
            a = temp

        # Add this chunk's hash to result so far.
        self.h0 = self.modular_add(self.h0, a)
        self.h1 = self.modular_add(self.h1, b)
        self.h2 = self.modular_add(self.h2, c)
        self.h3 = self.modular_add(self.h3, d)
        self.h4 = self.modular_add(self.h4, e)

    def __repr__(self):
        return f"SHA1Python(message={self.message!r}, hash={str(self)!r})"
