"""
Client class for handling communication with a server.
"""

from crypto.aes import Key
from crypto.rsa import PrivateKey, PublicKey, generate_keys
from protocol.connection import Connection
from protocol.session import Session


class Client:
    """
    Client class for handling communication with a server.

    Attributes:
        username: The username of the client.
        rsa_key_size: The size of the RSA key in bits. Default is 2048 bits.
        rsa_iterations: The number of iterations for RSA key generation. Default is 64.
        public_key: The public key of the client.
        private_key: The private key of the client.
        conn_key: The connection key used for encryption.
        conn: The connection object for communication.
        session: The session object for secure communication.
    """

    username: str
    rsa_key_size: int
    rsa_iterations: int
    public_key: PublicKey
    private_key: PrivateKey
    conn_key: Key | None
    conn: Connection | None
    session: Session | None

    def __init__(
        self, username: str, rsa_key_size: int = 2048, rsa_iterations: int = 64
    ) -> None:
        self.username = username
        self.rsa_key_size = rsa_key_size
        self.rsa_iterations = rsa_iterations
        self.private_key, self.public_key = generate_keys(rsa_key_size, rsa_iterations)
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
        # 1. Establish connection
        self.conn = Connection.connect(address, port)

        # 2. Exchange public keys
        server_public = PublicKey.from_bytes(self.conn.recv())
        self.conn.send(self.public_key.to_bytes())

        # 3. Send username
        self.conn.send(server_public.encrypt(self.username.encode()))

        # 4. Receive session key
        key_data = self.private_key.decrypt(self.conn.recv())
        self.conn_key = Key.from_bytes(key_data)

        # 5. Establish session
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
