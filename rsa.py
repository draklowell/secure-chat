class PrivateKey:
    def __init__(self, n: int, d: int):
        self.n = n
        self.d = d

    def decrypt(self, cipher: int) -> int:
        pass


class PublicKey:
    def __init__(self, n: int, e: int):
        self.n = n
        self.e = e

    def encrypt(self, message: int) -> int:
        pass

def generate_keys() -> tuple[PrivateKey, PublicKey]:
    pass
