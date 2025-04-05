from crypto.aes.block import decrypt_block, encrypt_block


def xor_block(a: memoryview, b: memoryview):
    """
    XOR second block into the first of 16 bytes each.

    Args:
        a: First block.
        b: Second block.
    """
    for i in range(16):
        a[i] ^= b[i]


def cbc_encrypt(message: bytes, iv: bytes, key: bytes, rounds: int) -> bytes:
    """
    Encrypts a message using AES in CBC mode.

    Args:
        message: The message to encrypt.
        iv: The initialization vector (IV).
        key: The encryption key.
        rounds: The number of rounds for AES.

    Returns:
        A tuple containing the encrypted message and the last IV used.
    """
    assert len(iv) == 16, "IV must be 16 bytes"
    assert len(key) in (16, 24, 32), "Key must be 16, 24, or 32 bytes"
    assert len(message) % 16 == 0, "Message length must be a multiple of 16 bytes"

    cipher = b""
    key = memoryview(key)
    block = memoryview(bytearray(iv))

    for i in range(0, len(message), 16):
        xor_block(block, message[i : i + 16])
        encrypt_block(key, block, rounds)
        cipher += bytes(block)

    return cipher, bytes(block)


def cbc_decrypt(
    crypto: bytes, iv: bytes, key: bytes, rounds: int
) -> tuple[bytes, bytes]:
    """
    Decrypts a message using AES in CBC mode.

    Args:
        crypto: The encrypted message.
        iv: The initialization vector (IV).
        key: The decryption key.
        rounds: The number of rounds for AES.

    Returns:
        A tuple containing the decrypted message and the last IV used.
    """
    assert len(iv) == 16, "IV must be 16 bytes"
    assert len(key) in (16, 24, 32), "Key must be 16, 24, or 32 bytes"
    assert len(crypto) % 16 == 0, "Cipher length must be a multiple of 16 bytes"

    message = b""
    key = memoryview(key)
    block = memoryview(bytearray(16))
    vector = memoryview(bytearray(iv))

    for i in range(0, len(crypto), 16):
        block[:] = crypto[i : i + 16]
        decrypt_block(key, block, rounds)
        xor_block(block, vector)
        message += bytes(block)

        vector[:] = crypto[i : i + 16]

    return message, vector
