"""
This module defines the Session class for handling secure communication over a connection.
"""

from crypto.aes import Key
from crypto.sha import SHA256
from protocol.connection import Connection


class Session:
    """
    Session class for handling secure communication over a connection.

    Attributes:
        conn: The connection object used for sending and receiving data.
        key: The encryption key used for securing messages.
    """

    conn: Connection
    key: Key

    def __init__(self, conn: Connection, key: Key):
        self.conn = conn
        self.key = key

    def send(self, message: bytes):
        """
        Send message over the session.

        Args:
            message: The message to send.
        """
        hash_ = SHA256.hash(message)
        data = message + hash_
        crypto = self.key.encrypt(data)
        self.conn.send(crypto)

    def recv(self) -> bytes:
        """
        Receive message from the session.

        Returns:
            The received message.
        """
        crypto = self.conn.recv()
        data = self.key.decrypt(crypto)
        message = data[: -SHA256.HASH_SIZE]
        hash_ = data[-SHA256.HASH_SIZE :]

        if hash_ != SHA256.hash(message):
            raise ValueError("Hash mismatch")

        return message
