import hashlib


class SHA256:
    """
    SHA256 hash algorithm.
    Works as an adapter for the hashlib library.

    Constants:
        HASH_SIZE: Size of the hash in bytes.
    """

    HASH_SIZE = 32

    @staticmethod
    def hash(data: bytes) -> bytes:
        """
        Hashes the given data using SHA256.

        Args:
            data: The data to hash.

        Returns:
            The SHA256 hash of the data.
        """
        return hashlib.sha256(data).digest()
