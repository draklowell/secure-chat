class GaloisField:
    """
    Galois Field GF(2^n) implementation.

    Attributes:
        modulus: Irreducible polynomial for the field. Default is 283 for AES.
    """

    modulus: int

    def __init__(self, modulus: int = 283):
        self.modulus = modulus

    def multiply(self, a: int, b: int) -> int:
        """
        Multiply two elements of GF(2^n).

        Args:
            a: First operand.
            b: Second operand.

        Returns:
            The product of the two operands.
        """
        # Bit mask to check whether A has the same degree as modulus
        bit_mask = 1 << (self.modulus.bit_length() - 1)
        c = 0
        while b:
            # Multiply A by constant term in B and add to result
            if b & 1:
                c ^= a

            # Multiply A and divide B by x
            b >>= 1
            a <<= 1

            # Bring A back to the field if overflows
            if a & bit_mask:
                a ^= self.modulus

        return c

    def transform(self, vector: memoryview, matrix: list[int]) -> bytearray:
        """
        Linearly transform vector in the GF(2^n) using the SQUARE matrix.

        Args:
            vector: The vector to be multiplied.
            matrix: The matrix to multiply with.

        Returns:
            The transformed vector.
        """
        size = len(vector)
        result = bytearray(size)
        for row in range(size):
            for col in range(size):
                result[row] ^= self.multiply(
                    vector[col], matrix[row * len(vector) + col]
                )

        return result


GF = GaloisField()
