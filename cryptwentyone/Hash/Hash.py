# cryptwentyone.Hash.SHA2.py
# CodeWriter21

import binascii as _binascii

from typing import Union as _Union

__all__ = ['Hash']


class Hash:
    X = 0x100000000  # 2**32
    name: str = 'hash'
    default_n_bits: int = 32

    def __init__(self, message: _Union[str, bytes]):
        if isinstance(message, str):
            message = message.encode()
        if not isinstance(message, bytes):
            raise TypeError("Message must be a string or bytes")
        self.message: bytes = message

        self._initialize_variables()

        self.ml = (len(self.message) * 8) % Hash.X

        self.hash: bytes = self._hash()

    def _initialize_variables(self):
        pass

    def left_rotate(self, x: int, n: int, bits: int = 0) -> int:
        """
        Rotates x to the left by n bits.

        :param x: The value to rotate.
        :param n: The number of bits to rotate.
        :return: The rotated value.
        """
        if bits < 1:
            bits = self.default_n_bits
        return ((x << n) | (x >> (bits - n))) % self.X

    def right_rotate(self, x: int, n: int, bits: int = 0) -> int:
        """
        Rotates x to the right by n bits.

        :param x: The value to rotate.
        :param n: The number of bits to rotate.
        :return: The rotated value.
        """
        if bits < 1:
            bits = self.default_n_bits
        return ((x << (bits - n)) | (x >> n)) % self.X

    def modular_add(self, *args) -> int:
        """
        Adds input numbers modulo X(default: 2**32).

        :return: The sum of the input numbers modulo 2**32.
        """
        return sum(args) % self.X

    def _hash(self) -> bytes:
        """
        Calculates the hash of the message.

        :return: The hash of the message.
        """

        # This method will be implemented by the child class.
        raise NotImplementedError('Child class must implement _hash method!')

    def _process_chunk(self, chunk: bytes):
        """
        Processes a chunk of the message.

        :param chunk: The chunk of the message.
        """

        # This method will be implemented by the child class.
        raise NotImplementedError('Child class must implement _hash method!')

    def hexdigest(self) -> str:
        """
        Returns the hash of the message as a hexadecimal string.

        :return: The hash of the message as a hexadecimal string.
        """
        return _binascii.hexlify(self.hash).decode()

    def __str__(self):
        return _binascii.hexlify(self.hash).decode()

    def __repr__(self):
        return f"Hash(message={self.message!r}, hash={str(self)!r})"

    def __eq__(self, other):
        return self.hash == other.hash

    def __hash__(self):
        return hash(self.hash)

    def __ne__(self, other):
        return self.hash != other.hash
