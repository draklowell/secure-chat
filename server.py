"""
Server module for a chat application.
"""

import threading

from crypto.aes import generate_key
from protocol.server import Server


def broadcast(server: Server):
    """
    Broadcast messages to all connected clients.
    """
    while True:
        message = input()

        if message == ":q":
            server.close()
            break
        elif message.startswith("::"):
            message = message[1:]

        server.broadcast(message)


if __name__ == "__main__":
    server = Server.create(
        "127.0.0.1", 9003, 1, generate_key(), input("Enter chatname: ")
    )
    try:
        threading.Thread(target=server.listen, daemon=True).start()
        broadcast(server)
    finally:
        server.close()
