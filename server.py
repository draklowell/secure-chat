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
        try:
            message = input()
        except (KeyboardInterrupt, EOFError):
            message = ":q"

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

    server = Server.create(
        address=hostname,
        port=port,
        backlog=100,
        chatname=chatname,
        aes_key_size=256,
        rsa_key_size=1024,
        rsa_iterations=16,
    )
    print(f"Ready to accept connections on {hostname}:{port}...")
    try:
        threading.Thread(target=server.listen, daemon=True).start()
        broadcast(server)
    finally:
        server.close()


if __name__ == "__main__":
    main()
