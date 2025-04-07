"""
This module implements a simple server for chat application.
"""

import socket
import string
import threading
from dataclasses import dataclass

from crypto.aes import Key
from crypto.rsa import PrivateKey, PublicKey, generate_keys
from protocol.connection import Connection
from protocol.session import Session


@dataclass
class ConnectedClient:
    """
    Represents a connected client.

    Attributes:
        username: The username of the client.
        conn: The connection object for the client.
        session: The session object for the client.
        key: The encryption key for the client.
    """

    username: str
    conn: Connection
    session: Session
    key: Key


class Server:
    """
    Server class for handling incoming connections and broadcasting messages.

    Attributes:
        sock: The socket object used for listening for incoming connections.
        public_key: The public key of the server.
        private_key: The private key of the server.
        aes_key_size: The size of the AES key in bits. Default is 256 bits.
        rsa_key_size: The size of the RSA key in bits. Default is 2048 bits.
        rsa_iterations: The number of iterations for RSA key generation. Default is 64.
        chatname: The chatname of the server.
        clients: A list of connected clients.
    """

    sock: socket.socket
    public_key: PublicKey
    private_key: PrivateKey
    aes_key_size: int
    rsa_key_size: int
    rsa_iterations: int
    chatname: str
    clients: dict[str, ConnectedClient]

    def __init__(
        self,
        sock: socket.socket,
        chatname: str,
        aes_key_size: int = 256,
        rsa_key_size: int = 2048,
        rsa_iterations: int = 64,
    ) -> None:
        if not self.validate_name(chatname):
            raise ValueError("Invalid chatname")

        self.sock = sock
        self.aes_key_size = aes_key_size
        self.rsa_key_size = rsa_key_size
        self.rsa_iterations = rsa_iterations
        self.private_key, self.public_key = generate_keys(rsa_key_size, rsa_iterations)
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
        cls,
        address: str,
        port: int,
        backlog: int,
        chatname: str,
        aes_key_size: int = 256,
        rsa_key_size: int = 2048,
        rsa_iterations: int = 64,
    ) -> "Server":
        """
        Create a server socket and bind it to the specified address and port.

        Args:
            address: The server address.
            port: The server port.
            backlog: The maximum number of queued connections.
            chatname: The chatname of the server.
            aes_key_size: The size of the AES key in bits. Default is 256 bits.
            rsa_key_size: The size of the RSA key in bits. Default is 2048 bits.
            rsa_iterations: The number of iterations for RSA key generation. Default is 64.

        Returns:
            An instance of the Server class.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((address, port))
        sock.listen(backlog)
        return cls(sock, chatname, aes_key_size, rsa_key_size, rsa_iterations)

    def accept(self) -> ConnectedClient | None:
        """
        Accept an incoming connection and return the username of the client.

        Returns:
            A ConnectedClient object if the connection is accepted, None otherwise.
        """
        # 1. Establish connection
        conn, _ = self.sock.accept()
        conn = Connection(conn)

        # 2. Exchange public keys
        conn.send(self.public_key.to_bytes())
        client_public = PublicKey.from_bytes(conn.recv())

        # 3. Receive username
        username = self.private_key.decrypt(conn.recv()).decode()
        if username == self.chatname or username in self.clients:
            conn.close()
            return None

        # 4. Send session key
        key = Key.generate(self.aes_key_size)
        key_cipher = client_public.encrypt(key.to_bytes())
        conn.send(key_cipher)

        # 5. Establish session
        session = Session(conn, key)

        self.broadcast(f"{username} has joined the chat")
        session.send(f'Welcome to the chat "{self.chatname}"'.encode())

        client = ConnectedClient(username, conn, session, key)
        self.clients[username] = client

        return client

    def listen(self):
        """
        Listen for incoming connections and handle them in separate threads.
        """
        while True:
            client = self.accept()
            if client is None:
                continue

            threading.Thread(target=self.handle, args=(client,), daemon=True).start()

    def broadcast(self, message: str):
        """
        Broadcast a message to all connected clients.

        Args:
            message: The message to broadcast.
        """
        for client in self.clients.values():
            client.session.send(f"{self.chatname}: {message}".encode())

    def handle(self, client: ConnectedClient):
        """
        Handle incoming messages from a client and broadcast them to all other clients.

        Args:
            client: The connected client.
        """
        while True:
            message = client.session.recv()
            for other in self.clients.values():
                if other.username == client.username:
                    continue

                other.session.send(f"{client.username}: ".encode() + message)

    def close(self):
        """
        Close the server socket and all client connections.
        """
        for client in self.clients.values():
            try:
                client.conn.close()
            except:
                pass

        self.sock.close()
