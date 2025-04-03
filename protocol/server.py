"""
This module implements a simple server for chat application.
"""

import socket
import string
import threading

from crypto.aes import Key
from crypto.rsa import PublicKey
from protocol.connection import Connection
from protocol.session import Session


class Server:
    """
    Server class for handling incoming connections and broadcasting messages.

    Attributes:
        sock: The socket object used for listening for incoming connections.
        key: The encryption key used for securing messages.
        chatname: The chatname of the server.
        clients: A list of connected clients.
    """

    sock: socket.socket
    key: Key
    chatname: str
    clients: dict[str, tuple[Connection, Session]]

    def __init__(self, sock: socket.socket, key: Key, chatname: str) -> None:
        if not self.validate_name(chatname):
            raise ValueError("Invalid chatname")

        self.sock = sock
        self.key = key
        self.chatname = chatname
        self.clients = {}

    @staticmethod
    def validate_name(name: str) -> bool:
        """
        Validate the username.

        Args:
            name: The username to validate.

        Returns:
            True if the username is valid, False otherwise.
        """
        if not 0 < len(name) <= 32:
            return False

        for char in name:
            if char not in string.ascii_letters + string.digits + "_":
                return False

        return True

    @classmethod
    def create(
        cls, address: str, port: int, backlog: int, key: Key, chatname: str
    ) -> "Server":
        """
        Create a server socket and bind it to the specified address and port.

        Args:
            address: The server address.
            port: The server port.
            backlog: The maximum number of queued connections.
            key: The encryption key to use.
            chatname: The chatname of the server.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((address, port))
        sock.listen(backlog)
        return cls(sock, key, chatname)

    def accept(self) -> str:
        """
        Accept an incoming connection and return the username of the client.

        Returns:
            The username of the client.
        """
        conn, _ = self.sock.accept()
        conn = Connection(conn)
        username = conn.recv().decode()
        if username == self.chatname or username in self.clients:
            conn.close()
            return None

        public_key = PublicKey.from_bytes(conn.recv())
        crypto = public_key.encrypt(self.key.to_bytes())
        conn.send(crypto)

        session = Session(conn, self.key)

        self.broadcast(f"{username} has joined the chat")
        session.send(f'Welcome to the chat "{self.chatname}"'.encode())

        self.clients[username] = (conn, session)

        return username

    def listen(self):
        """
        Listen for incoming connections and handle them in separate threads.
        """
        while True:
            username = self.accept()
            if username is None:
                continue

            threading.Thread(target=self.handle, args=(username,), daemon=True).start()

    def broadcast(self, message: str):
        """
        Broadcast a message to all connected clients.

        Args:
            message: The message to broadcast.
        """
        # Actually a little unefficient because of encrypting message
        # for each client separately, but this is a simple example
        for _, session in self.clients.values():
            session.send(f"{self.chatname}: {message}".encode())

    def handle(self, username: str):
        """
        Handle incoming messages from a client and broadcast them to all other clients.

        Args:
            username: The username of the client.
        """
        _, session = self.clients[username]
        while True:
            message = session.recv()
            for other_username, (_, other_session) in self.clients.items():
                if other_username == username:
                    continue

                other_session.send(f"{username}: ".encode() + message)

    def close(self):
        """
        Close the server socket and all client connections.
        """
        for _, (conn, _) in self.clients.items():
            try:
                conn.close()
            except:
                pass

        self.sock.close()
