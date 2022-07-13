# cryptwentyone.Hash.MD5.py
# CodeWriter21

import binascii as _binascii

from typing import Union as _Union

__all__ = ['MD5Python']


K = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

# s specifies the per-calculated shift amounts
s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
     5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
     4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
     6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

WORD_A = 0x67452301
WORD_B = 0xefcdab89
WORD_C = 0x98badcfe
WORD_D = 0x10325476


class MD5Python:
    X = 2 ** 32

    def __init__(self, message: _Union[str, bytes]):
        if isinstance(message, str):
            message = message.encode()
        if not isinstance(message, bytes):
            raise TypeError("Message must be a string or bytes")
        self.message: bytes = message

        self.a0: int = WORD_A
        self.b0: int = WORD_B
        self.c0: int = WORD_C
        self.d0: int = WORD_D

        self.hash: bytes = self.__hash()

    @staticmethod
    def left_rotate(x: int, n: int) -> int:
        """
        Rotates x to the left by n bits.

        :param x: The value to rotate.
        :param n: The number of bits to rotate.
        :return: The rotated value.
        """
        return (x << n) | (x >> (32 - n))

    @staticmethod
    def modular_add(x: int, y: int) -> int:
        """
        Adds x and y modulo 2**32.

        :param x: The first value.
        :param y: The second value.
        :return: The sum of x and y modulo 2**32.
        """
        return (x + y) % MD5Python.X

    def __hash(self) -> bytes:
        """
        Calculates the MD5 hash of the message.

        :return: The MD5 hash of the message.
        """
        # Pad the message with a 1 bit followed by 0 bits.
        message = self.message + b"\x80"  # 0b10000000

        # Pad the message with 0 bits until its length is a multiple of 512 bits.
        modulo_length = len(message) % 64
        message += b"\x00" * ((56 - modulo_length) if modulo_length <= 56 else (56 + 64 - modulo_length))

        # Append a 64-bit representation of the original message's length
        message += (len(self.message) * 8).to_bytes(8, 'little')

        # Process the padded message in successive 512-bit chunks.
        for i in range(0, len(message), 64):
            self.__process_chunk(message[i:i + 64])

        # Return the result as bytes
        return self.a0.to_bytes(4, 'little') + self.b0.to_bytes(4, 'little') + self.c0.to_bytes(4, 'little') + \
               self.d0.to_bytes(4, 'little')

    def __process_chunk(self, chunk: bytes):
        """
        Processes a 512-bit chunk of the message.

        :param chunk: The 512-bit chunk of the message.
        """
        # Break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15.
        w = [0] * 16
        for j in range(16):
            w[j] = int.from_bytes(chunk[j * 4:j * 4 + 4], byteorder="little")

        # Initialize hash value for this chunk.
        a = self.a0
        b = self.b0
        c = self.c0
        d = self.d0

        # Main loop.
        for i in range(64):
            if 0 <= i <= 15:
                temp = (b & c) | ((~b) & d)
                g = i
            elif 16 <= i <= 31:
                temp = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                temp = b ^ c ^ d
                g = (3 * i + 5) % 16
            elif 48 <= i <= 63:
                temp = c ^ (b | (~d))
                g = (7 * i) % 16
            temp = self.modular_add(temp, a)
            temp = self.modular_add(temp, K[i])
            temp = self.modular_add(temp, w[g])
            a = d
            d = c
            c = b
            b = b + self.left_rotate(temp, s[i])

        # Add this chunk's hash to result so far.
        self.a0 = self.modular_add(self.a0, a)
        self.b0 = self.modular_add(self.b0, b)
        self.c0 = self.modular_add(self.c0, c)
        self.d0 = self.modular_add(self.d0, d)

    def hexdigest(self) -> str:
        """
        Returns the MD5 hash of the message as a hexadecimal string.

        :return: The MD5 hash of the message as a hexadecimal string.
        """
        return _binascii.hexlify(self.hash).decode()

    def __str__(self):
        return _binascii.hexlify(self.hash).decode()

    def __repr__(self):
        return f"MD5Python(message={self.message!r}, hash={str(self)!r})"

    def __eq__(self, other):
        return self.hash == other.hash

    def __hash__(self):
        return hash(self.hash)

    def __ne__(self, other):
        return self.hash != other.hash
