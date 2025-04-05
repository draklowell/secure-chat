from crypto.aes.constants import (
    AES_MIXING_MATRIX,
    AES_MIXING_MATRIX_INVERSE,
    AES_SBOX,
    AES_SBOX_INVERSE,
)
from crypto.aes.galois_field import GF


def sub_bytes(state: memoryview):
    """
    Substitute bytes in the state using the S-Box.

    Args:
        state: The state to be transformed.
    """
    for idx, value in enumerate(state):
        state[idx] = AES_SBOX[value]


def sub_bytes_inverse(state: memoryview):
    """
    Substitute bytes in the state using the inverse S-Box.

    Args:
        state: The state to be transformed.
    """
    for idx, value in enumerate(state):
        state[idx] = AES_SBOX_INVERSE[value]


def shift_rows(state: memoryview):
    """
    Shift rows in the state to the left.

    Args:
        state: The state to be transformed.
    """
    # Shift second row 1 to the left
    (state[1], state[5], state[9], state[13]) = (
        state[5],
        state[9],
        state[13],
        state[1],
    )

    # Shift third row 2 to the left
    (state[2], state[6], state[10], state[14]) = (
        state[10],
        state[14],
        state[2],
        state[6],
    )

    # Shift fourth row 3 to the left
    (state[3], state[7], state[11], state[15]) = (
        state[15],
        state[3],
        state[7],
        state[11],
    )


def shift_rows_inverse(state: memoryview):
    """
    Shift rows in the state to the right.

    Args:
        state: The state to be transformed.
    """
    # Shift second row 1 to the right
    (state[1], state[5], state[9], state[13]) = (
        state[13],
        state[1],
        state[5],
        state[9],
    )

    # Shift third row 2 to the right
    (state[2], state[6], state[10], state[14]) = (
        state[10],
        state[14],
        state[2],
        state[6],
    )

    # Shift fourth row 3 to the right
    (state[3], state[7], state[11], state[15]) = (
        state[7],
        state[11],
        state[15],
        state[3],
    )


def mix_columns(state: memoryview):
    """
    Mix columns in the state using the AES mixing matrix.

    Args:
        state: The state to be transformed.
    """
    for col in range(4):
        state[col * 4 : col * 4 + 4] = GF.transform(
            state[col * 4 : col * 4 + 4],
            AES_MIXING_MATRIX,
        )


def mix_columns_inverse(state: memoryview):
    """
    Mix columns in the state using the inverse AES mixing matrix.

    Args:
        state: The state to be transformed.
    """
    for col in range(4):
        state[col * 4 : col * 4 + 4] = GF.transform(
            state[col * 4 : col * 4 + 4],
            AES_MIXING_MATRIX_INVERSE,
        )


def add_round_key(state: memoryview, key: memoryview):
    """
    Add round key to the state.

    Args:
        state: The state to be transformed.
        key: The round key to be added.
    """
    for idx in range(16):
        state[idx] ^= key[idx]


def sub_word(word: memoryview):
    """
    Substitute word using the S-Box.

    Args:
        word: The word to be transformed.
    """
    for idx in range(4):
        word[idx] = AES_SBOX[word[idx]]


def rot_word(word: memoryview):
    """
    Rotate word to the left.

    Args:
        word: The word to be transformed.
    """
    (word[0], word[1], word[2], word[3]) = (
        word[1],
        word[2],
        word[3],
        word[0],
    )


def xor_word(word1: memoryview, word2: memoryview):
    """
    XOR second word into the first.

    Args:
        word1: The first word.
        word2: The second word.
    """
    for idx in range(4):
        word1[idx] ^= word2[idx]


def get_word(state: memoryview, index: int) -> memoryview:
    """
    Get a word from the state.

    Args:
        state: The state to be transformed.
        index: The index of the word to be retrieved.

    Returns:
        The word at the specified index.
    """
    return state[index * 4 : index * 4 + 4]


def expand_key(key: memoryview, rounds: int) -> list[memoryview]:
    """
    Expand the key for AES encryption.

    Args:
        key: The original key.
        rounds: The number of rounds for AES encryption.

    Returns:
        A list of expanded keys for each round.
    """
    assert len(key) in (16, 24, 32), "Key length must be 16, 24, or 32 bytes"
    assert rounds in (10, 12, 14), "Number of rounds must be 10, 12, or 14"

    key_length = len(key) // 4
    rc = 1
    schedule = memoryview(bytearray(4 * 4 * (rounds + 1)))

    for i in range(4 * (rounds + 1)):
        cur = get_word(schedule, i)
        if i < key_length:
            cur[:] = get_word(key, i)
        elif i % key_length == 0:
            cur[:] = get_word(schedule, i - 1)
            rot_word(cur)
            sub_word(cur)
            xor_word(cur, get_word(schedule, i - key_length))
            cur[0] ^= rc
            rc = GF.multiply(rc, 2)
        elif key_length > 6 and i % key_length == 4:
            cur[:] = get_word(schedule, i - 1)
            sub_word(cur)
            xor_word(cur, get_word(schedule, i - key_length))
        else:
            cur[:] = get_word(schedule, i - 1)
            xor_word(cur, get_word(schedule, i - key_length))

    return [schedule[i * 16 : i * 16 + 16] for i in range(rounds + 1)]


def encrypt_block(key: memoryview, block: memoryview, rounds: int) -> memoryview:
    """
    Encrypt a block of data using AES encryption. Encrypts in-place.

    Args:
        key: The encryption key.
        block: The block of data to be encrypted.
        rounds: The number of rounds for AES encryption.
    """
    assert len(block) == 16, "Block length must be 16 bytes"

    round_keys = expand_key(key, rounds)
    add_round_key(block, round_keys[0])
    for i in range(1, rounds):
        sub_bytes(block)
        shift_rows(block)
        mix_columns(block)
        add_round_key(block, round_keys[i])

    sub_bytes(block)
    shift_rows(block)
    add_round_key(block, round_keys[rounds])


def decrypt_block(key: memoryview, block: memoryview, rounds: int) -> memoryview:
    """
    Decrypt a block of data using AES decryption. Decrypts in-place.

    Args:
        key: The decryption key.
        block: The block of data to be decrypted.
        rounds: The number of rounds for AES decryption.
    """
    assert len(block) == 16, "Block length must be 16 bytes"

    round_keys = expand_key(key, rounds)
    round_keys.reverse()
    add_round_key(block, round_keys[0])
    shift_rows_inverse(block)
    sub_bytes_inverse(block)

    for i in range(1, rounds):
        add_round_key(block, round_keys[i])
        mix_columns_inverse(block)
        shift_rows_inverse(block)
        sub_bytes_inverse(block)

    add_round_key(block, round_keys[rounds])
