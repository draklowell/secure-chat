"""rsa"""
import secrets
from math import gcd

class PrivateKey:
    """class privatekey"""
    def __init__(self, n: int, d: int):
        self.n = n
        self.d = d

    def decrypt(self, cipher_bytes: bytes, private_key) -> bytes:
        """Decrypting the message"""
        d, n = private_key
        c = int.from_bytes(cipher_bytes, "big")
        m = pow(c, d, n)
        plaintext_bytes = m.to_bytes(byteorder="big")
        return plaintext_bytes


class PublicKey:
    """class publickey"""
    def __init__(self, n: int, e: int):
        self.n = n
        self.e = e

    def encrypt(self, message: bytes, public_key) -> bytes:
        """Encrypting the message"""
        e, n = public_key
        m = int.from_bytes(message, "big")
        c = pow(m, e, n)
        cipher_bytes = c.to_bytes(byteorder="big")
        return cipher_bytes


    def to_bytes(self) -> bytes:
        """convert to bytes"""
        n_bytes = self.n.to_bytes(4, byteorder="big")
        e_bytes = self.e.to_bytes(4, byteorder="big")
        return n_bytes + e_bytes
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicKey":
        """convert from bytes"""
        n = int.from_bytes(data[:4], byteorder="big")
        e = int.from_bytes(data[4:], byteorder="big")
        return cls(n, e)

def is_prime(n, k=128):
    """Checking the primality of a number"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    for _ in range(k):
        a = secrets.randbelow(n-1) + 2
        if pow(a, n - 1, n) != 1:
            return False
    return True

def generate_prime(bits):
    """Generating a prime number of a given number of bits"""
    while True:
        p = secrets.randbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p

def generate_keys(bits=2048) -> tuple[PrivateKey, PublicKey]:
    """RSA public and private key generation"""
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        while gcd(e, phi) != 1:
            e += 2
        d = pow(e, -1, phi)
        return (e, n), (d, n)
