"""
Module for connection wrapper to handle sending and receiving data over a socket in chunks.
"""

import socket
import threading


class Connection:
    """
    A class to handle sending and receiving data thread-safely over a socket in chunks.

    Attributes:
        conn: The socket connection to use for sending and receiving data.
        recv_lock: A threading lock for receiving data.
        send_lock: A threading lock for sending data.
    """

    conn: socket.socket
    recv_lock: threading.Lock
    send_lock: threading.Lock

    def __init__(self, conn: socket.socket):
        self.conn = conn
        self.recv_lock = threading.Lock()
        self.send_lock = threading.Lock()

    @classmethod
    def connect(cls, address: str, port: int) -> "Connection":
        """
        Connect to a server at the specified address and port.

        Args:
            address: The server address.
            port: The server port.

        Returns:
            A Connection object.
        """
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((address, port))
        return cls(conn)

    def close(self):
        """
        Close the socket connection.
        """
        self.conn.close()

    def _send_chunk(self, chunk: bytes, is_last: bool = True):
        if len(chunk) > 32767:
            raise ValueError("Chunk length exceeds maximum limit of 32767 bytes.")

        header = (is_last << 15) | (len(chunk) - 1)
        self.conn.send(header.to_bytes(2, byteorder="big"))
        self.conn.send(chunk)

    def _recv_chunk(self) -> tuple[bytes, bool]:
        header = int.from_bytes(self.conn.recv(2), byteorder="big")
        is_last = bool(header >> 15)
        length = (header & 0x7FFF) + 1

        chunk = b""
        while len(chunk) < length:
            chunk += self.conn.recv(length - len(chunk))

        return chunk, is_last

    def send(self, data: bytes):
        """
        Send data in chunks over the socket connection.

        Thread-safe method.

        Args:
            data: The data to be sent.
        """
        with self.send_lock:
            total_length = len(data)
            if total_length == 0:
                raise ValueError("Data length must be greater than 0.")

            offset = 0

            while offset < total_length:
                chunk_size = min(32767, total_length - offset)
                is_last = (offset + chunk_size) == total_length
                chunk = data[offset : offset + chunk_size]

                self._send_chunk(chunk, is_last)
                offset += chunk_size

            # print(f"Sent packet: {data!r}")

    def recv(self) -> bytes:
        """
        Receive data in chunks from the socket connection.

        Thread-safe method.

        Returns:
            The received data.
        """
        with self.recv_lock:
            data = b""
            is_last = False
            while not is_last:
                chunk, is_last = self._recv_chunk()
                data += chunk

            # print(f"Received packet: {data!r}")

            return data
