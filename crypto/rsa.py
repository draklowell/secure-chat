class PrivateKey:
    def __init__(self, n: int, d: int):
        self.n = n
        self.d = d

    def decrypt(self, cipher: bytes) -> bytes:
        return cipher


class PublicKey:
    def __init__(self, n: int, e: int):
        self.n = n
        self.e = e

    def encrypt(self, message: bytes) -> bytes:
        return message

    def to_bytes(self) -> bytes:
        n_bytes = self.n.to_bytes(4, byteorder="big")
        e_bytes = self.e.to_bytes(4, byteorder="big")
        return n_bytes + e_bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicKey":
        n = int.from_bytes(data[:4], byteorder="big")
        e = int.from_bytes(data[4:], byteorder="big")
        return cls(n, e)


def generate_keys() -> tuple[PrivateKey, PublicKey]:
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    d = pow(e, -1, phi)
    return PrivateKey(n, d), PublicKey(n, e)
