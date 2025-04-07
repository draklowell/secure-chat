import secrets

from crypto.aes.modes import cbc_decrypt, cbc_encrypt


class Key:
    """
    AES key class.

    Attributes:
        rounds: Number of rounds for AES encryption.
        key: The encryption key.
        iv: The last initialization vector (IV).
    """

    rounds: int
    key: bytes
    iv: bytes

    def __init__(self, key: bytes, iv: bytes):
        assert len(key) in (16, 24, 32), "Key must be 16, 24, or 32 bytes"
        assert len(iv) == 16, "IV must be 16 bytes"

        match len(key):
            case 16:
                self.rounds = 10
            case 24:
                self.rounds = 12
            case 32:
                self.rounds = 14

        self.key = key
        self.iv = iv

    def copy(self) -> "Key":
        """
        Creates a copy of the Key instance.

        Returns:
            A new Key instance with the same key and IV.
        """
        return Key(self.key, self.iv)

    def encrypt(self, message: bytes) -> bytes:
        """
        Encrypts a message using AES in CBC mode.

        Args:
            message: The message to encrypt.

        Returns:
            The encrypted message.
        """
        # Padding the message to be a multiple of 16 bytes
        padding_length = 16 - len(message) % 16
        message += bytes([padding_length] * padding_length)

        cipher, self.iv = cbc_encrypt(message, self.iv, self.key, self.rounds)
        return cipher

    def decrypt(self, cipher: bytes) -> bytes:
        """
        Decrypts a message using AES in CBC mode.

        Args:
            cipher: The encrypted message.

        Returns:
            The decrypted message.
        """
        message, self.iv = cbc_decrypt(cipher, self.iv, self.key, self.rounds)

        # Removing padding
        padding_length = message[-1]
        return message[:-padding_length]

    def to_bytes(self) -> bytes:
        """
        Serializes the key and IV to bytes.

        Returns:
            The serialized bytes.
        """
        return len(self.key).to_bytes(1, "big") + self.key + self.iv

    @classmethod
    def from_bytes(cls, data: bytes) -> "Key":
        """
        Deserializes the key and IV from bytes.

        Args:
            data: The serialized bytes.

        Returns:
            An instance of the Key class.
        """
        key_length = data[0]
        return cls(
            key=data[1 : 1 + key_length], iv=data[1 + key_length : 1 + key_length + 16]
        )

    @classmethod
    def generate(cls, size: int) -> "Key":
        """
        Generates a random AES key and IV.

        Args:
            size: The size of the key in bits. Must be 128, 192, or 256.

        Returns:
            An instance of the Key class with a random key and IV.
        """
        assert size in {128, 192, 256}, "Key size must be 128, 192, or 256 bits"
        return Key(
            key=secrets.token_bytes(size // 8),
            iv=secrets.token_bytes(16),
        )
