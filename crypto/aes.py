class Key:
    def __init__(self):
        pass

    def encrypt(self, message: bytes) -> bytes:
        return message

    def decrypt(self, cipher: bytes) -> bytes:
        return cipher

    def to_bytes(self) -> bytes:
        return b"\x00\x00\x00\x00"

    @classmethod
    def from_bytes(cls, data: bytes) -> "Key":
        return cls()


def generate_key() -> Key:
    return Key()
