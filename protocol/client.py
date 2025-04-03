"""
Client class for handling communication with a server.
"""

from crypto.aes import Key
from crypto.rsa import PrivateKey, PublicKey
from protocol.connection import Connection
from protocol.session import Session


class Client:
    """
    Client class for handling communication with a server.

    Attributes:
        username: The username of the client.
        private_key: The private key of the client.
        public_key: The public key of the client.
        conn_key: The connection key used for encryption.
        conn: The connection object for communication.
        session: The session object for secure communication.
    """

    username: str
    private_key: PrivateKey
    public_key: PublicKey
    conn_key: Key | None
    conn: Connection | None
    session: Session | None

    def __init__(
        self, username: str, private_key: PrivateKey, public_key: PublicKey
    ) -> None:
        self.username = username
        self.private_key = private_key
        self.public_key = public_key
        self.conn_key = None
        self.conn = None
        self.session = None

    def connect(self, address: str, port: int):
        """
        Connect to the server at the specified address and port.

        Args:
            address: The server address.
            port: The server port.
        """
        self.conn = Connection.connect(address, port)

        self.conn.send(self.username.encode())
        self.conn.send(self.public_key.to_bytes())

        self.conn_key = Key.from_bytes(self.conn.recv())
        self.session = Session(self.conn, self.conn_key)

    def disconnect(self):
        """
        Disconnect from the server.
        """
        if not self.conn:
            raise ValueError("Connection not established")

        self.conn.close()
        self.conn = None
        self.conn_key = None
        self.session = None

    def send(self, message: str):
        """
        Send a message to the server.

        Args:
            message: The message to send.
        """
        if not self.session:
            raise ValueError("Session not established")

        self.session.send(message.encode())

    def recv(self) -> str:
        """
        Receive a message from the server.

        Returns:
            The received message.
        """
        if not self.conn:
            raise ValueError("Session not established")

        return self.session.recv().decode()
