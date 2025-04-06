"""
This module defines the Session class for handling secure communication over a connection.
"""

from crypto.aes import Key
from crypto.sha import SHA256
from protocol.connection import Connection


class Session:
    """
    Session class for handling secure communication over a connection.
    Different keys for sending and receiving data are used to ensure iv synchronization.

    Attributes:
        conn: The connection object used for sending and receiving data.
        recv_key: The key used for incoming messages.
        send_key: The key used for outgoing messages.
    """

    conn: Connection
    recv_key: Key
    send_key: Key

    def __init__(self, conn: Connection, key: Key):
        self.conn = conn
        self.recv_key = key.copy()
        self.send_key = key.copy()

    def send(self, message: bytes):
        """
        Send message over the session.

        Args:
            message: The message to send.
        """
        hash_ = SHA256.hash(message)
        data = message + hash_
        crypto = self.send_key.encrypt(data)
        self.conn.send(crypto)

    def recv(self) -> bytes:
        """
        Receive message from the session.

        Returns:
            The received message.
        """
        crypto = self.conn.recv()
        data = self.recv_key.decrypt(crypto)
        message = data[: -SHA256.HASH_SIZE]
        hash_ = data[-SHA256.HASH_SIZE :]

        if hash_ != SHA256.hash(message):
            raise ValueError("Hash mismatch")

        return message
