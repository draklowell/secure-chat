"""RSA Encryption and Decryption"""

import secrets
from math import gcd


class PrivateKey:
    """
    RSA Private Key.

    Attributes:
        n: The modulus for the public key.
        d: The private exponent.
    """

    n: int
    d: int

    def __init__(self, n: int, d: int):
        self.n = n
        self.d = d

    def decrypt(self, cipher: bytes) -> bytes:
        """
        Decrypt the message.

        Args:
            cipher: The encrypted message.

        Returns:
            The decrypted message.
        """
        c = int.from_bytes(cipher, "big")
        m = pow(c, self.d, self.n)
        plaintext = m.to_bytes((m.bit_length() + 7) // 8, byteorder="big")
        return plaintext


class PublicKey:
    """
    RSA Public Key.

    Attributes:
        n: The modulus for the public key.
        e: The public exponent.
    """

    n: int
    e: int

    def __init__(self, n: int, e: int):
        self.n = n
        self.e = e

    def encrypt(self, message: bytes) -> bytes:
        """
        Encrypt the message.

        Args:
            message: The plaintext message.

        Returns:
            The encrypted message.
        """
        m = int.from_bytes(message, "big")
        if m >= self.n:
            raise ValueError("Message is too large for the key size")

        c = pow(m, self.e, self.n)
        cipher = c.to_bytes((c.bit_length() + 7) // 8, byteorder="big")
        return cipher

    def to_bytes(self) -> bytes:
        """
        Convert the public key to bytes.

        Returns:
            The serialized bytes.
        """
        e_bytes = self.e.to_bytes(4, byteorder="big")
        n_bytes = self.n.to_bytes((self.n.bit_length() + 7) // 8, byteorder="big")
        return e_bytes + n_bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicKey":
        """
        Convert bytes to a PublicKey instance.

        Args:
            data: The serialized bytes.

        Returns:
            An instance of the PublicKey class.
        """
        e = int.from_bytes(data[:4], byteorder="big")
        n = int.from_bytes(data[4:], byteorder="big")
        return cls(n, e)


def is_prime(n: int, k: int) -> bool:
    """
    Fermat's primality test.

    Args:
        n: The number to test for primality.
        k: The number of iterations for the test.

    Returns:
        True if n is probably prime, False otherwise.
    """
    if n <= 1:
        return False
    if n <= 3:
        return True

    for _ in range(k):
        a = secrets.randbelow(n - 1) + 2
        if pow(a, n - 1, n) != 1:
            return False

    return True


def generate_prime(bits: int, k: int) -> int:
    """
    Generate a prime number of specified bit length.

    Args:
        bits: The bit length of the prime number.
        k: The number of iterations for the primality test.

    Returns:
        A prime number of the specified bit length.
    """
    while True:
        p = secrets.randbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p, k):
            return p


def generate_keys(bits: int = 2048, k: int = 64) -> tuple[PrivateKey, PublicKey]:
    """
    Generate RSA public and private keys.

    Args:
        bits: The bit length of the keys. Default is 2048.
        k: The number of iterations for the primality test. Default is 64.

    Returns:
        A tuple containing the public key and the private key.
    """
    while True:
        p = generate_prime(bits // 2, k)
        q = generate_prime(bits // 2, k)

        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        while gcd(e, phi) != 1:
            e += 2

        d = pow(e, -1, phi)
        return PrivateKey(n, d), PublicKey(n, e)
