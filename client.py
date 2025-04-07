"""
Client module for a chat application.
"""

import threading

from protocol.client import Client


def read(client: Client):
    """
    Read messages from the server and print them to the console.
    """
    while True:
        message = client.recv()
        print(message)


def send(client: Client):
    """
    Send messages from the console to the server.
    """
    while True:
        try:
            message = input()
        except (KeyboardInterrupt, EOFError):
            message = ":q"

        if message == ":q":
            client.disconnect()
            break
        elif message.startswith("::"):
            message = message[1:]

        client.send(message)


def main():
    """
    Main function to run the client.
    """
    username = input("Enter your name: ")
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

    client = Client(
        username=username,
        rsa_key_size=1024,
        rsa_iterations=16,
    )
    print("Connecting to the server...")
    client.connect(hostname, port)
    threading.Thread(target=read, args=(client,), daemon=True).start()
    send(client)


if __name__ == "__main__":
    main()
