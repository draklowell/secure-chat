import hashlib


class SHA256:
    HASH_SIZE = 32

    @staticmethod
    def hash(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()
