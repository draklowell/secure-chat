"""
Server module for a chat application.
"""

import threading

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


def main():
    """
    Main function to run the server.
    """
    chatname = input("Enter chat name: ")
    host = input("Enter the server address: ").split(":")

    hostname = ""
    port = 9000
    if len(host) == 2:
        hostname, port = host
        port = int(port)
    elif len(host) == 1:
        hostname = host[0]

    if not hostname:
        hostname = "localhost"

    server = Server.create(hostname, port, 100, chatname, 32, 512, 16)
    print(f"Ready to accept connections on {hostname}:{port}...")
    try:
        threading.Thread(target=server.listen, daemon=True).start()
        broadcast(server)
    finally:
        server.close()


if __name__ == "__main__":
    main()
