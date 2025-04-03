"""
Client module for a chat application.
"""

import threading

from crypto.rsa import generate_keys
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
        message = input()

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
    client = Client(input("Enter you username: "), *generate_keys())
    client.connect("127.0.0.1", 9003)
    threading.Thread(target=read, args=(client,), daemon=True).start()
    send(client)


if __name__ == "__main__":
    main()
