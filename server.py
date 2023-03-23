# Server side of messenger app

# The python-doubleratchet package was used to implement the Double Ratchet algorithm:
#   https://pypi.org/project/DoubleRatchet/
#   https://github.com/Syndace/python-doubleratchet

# pip3 install -r requirements.txt


from typing import Any, Dict, List

import asyncio
import socket
import select
import sys
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from doubleratchet import DoubleRatchet as DR, EncryptedMessage, Header
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve448 as dhr448,
    HashFunction,
    kdf_hkdf,
    kdf_separate_hmacs
)


# The following is recommended by python-doubleratchet:
#===============================================================

class DoubleRatchet(DR):
    """
    An example of a Double Ratchet implementation.
    """
    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return (
            associated_data
            + header.ratchet_pub
            + header.sending_chain_length.to_bytes(8, "big")
            + header.previous_sending_chain_length.to_bytes(8, "big")
        )


class DiffieHellmanRatchet(dhr448.DiffieHellmanRatchet):
    """
    Use the recommended X448-based Diffie-Hellman ratchet implementation in this example.
    """


class AEAD(aead_aes_hmac.AEAD):
    """
    Use the recommended AES/HMAC-based AEAD implementation in this example, 
    with SHA-512 and a fitting info string.
    """
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "Double Ratchet Chat AEAD".encode("ASCII")


class RootChainKDF(kdf_hkdf.KDF):
    """
    Use the recommended HKDF-based KDF implementation for the root chain in this example, 
    with SHA-512 and a fitting info string.
    """
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "Double Ratchet Chat Root Chain KDF".encode("ASCII")


class MessageChainKDF(kdf_separate_hmacs.KDF):
    """
    Use the recommended separate HMAC-based KDF implementation for the message chain in this example, 
    with truncated SHA-512.
    """
    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256


# Configuration of the DoubleRatchet class, which has to be passed to each constructing method
# (encrypt_initial_message, decrypt_initial_message, deserialize).
dr_configuration: Dict[str, Any] = {
    "diffie_hellman_ratchet_class": DiffieHellmanRatchet,
    "root_chain_kdf": RootChainKDF,
    "message_chain_kdf": MessageChainKDF,
    "message_chain_constant": b"\x01\x02",
    "dos_protection_threshold": 100,
    "max_num_skipped_message_keys": 1000,
    "aead": AEAD
}


# Messenger functionality starts here:
#===============================================================

class Client():
    def __init__(self, connection=None, address=None) -> None:
        self.connection = connection
        self.address = address
        self.double_ratchet: DoubleRatchet = None

    def get_encrypted_message(self, message: bytes, associated_data: bytes) -> EncryptedMessage:
        return self.double_ratchet.encrypt_message(message, associated_data)

    def send_encrypted_message(self, encrypted_message: EncryptedMessage) -> None:
        to_send = encrypted_message.header.ratchet_pub  # len == 56
        to_send += encrypted_message.header.previous_sending_chain_length.to_bytes(10, "big")
        to_send += encrypted_message.header.sending_chain_length.to_bytes(10, "big")
        to_send += encrypted_message.ciphertext
        self.connection.send(to_send)

    async def send_message(self, message: bytes, associated_data: bytes) -> None:
        encrypted_message = await self.get_encrypted_message(message, associated_data)
        self.send_encrypted_message(encrypted_message)

    async def get_decrypted_message(self, encrypted_message: EncryptedMessage, associated_data: bytes) -> bytes:
        return await self.double_ratchet.decrypt_message(encrypted_message, associated_data)


def main():
    if len(sys.argv) != 4:
        print("Correct usage: python3 client.py [IP ADDRESS] [PORT] [PASSWORD]")
        return
    
    ip_address = str(sys.argv[1])
    port = int(sys.argv[2])
    password = str(sys.argv[3])

    # The shared secret must be 32 bytes, 
    # so the password cannot be more than 32 bytes long.
    # To create the shared secret from the password,
    # the password must be extended to 32 bytes if
    # it is not already 32 characters long.
    assert len(password) <= 32 

    associated_data = "Some Associated Data".encode("ASCII")
    shared_secret = extend_to_32_char(password).encode("ASCII")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server.bind((ip_address, port))
    server.listen(10) # Max of 10 clients

    print("Server running...\n")

    clients = []
    while True:
        connection, address = server.accept()
        client = Client(connection, address)
        clients.append(client)

        # When a client connects, a new thread is started to handle
        # communication between the server and client.
        new_client_thread = threading.Thread(
            target=client_thread_loop, 
            args=(server, clients, client, associated_data, shared_secret)
        )
        new_client_thread.start()

    server.close()


def extend_to_32_char(message: str) -> str:
    message += " " * (32 - len(message))
    return message


def client_thread_loop(server, clients: List[Client], client: Client, associated_data, shared_secret) -> None:
    asyncio.run(client_thread(server, clients, client, associated_data, shared_secret))


async def client_thread(server, clients: List[Client], client: Client, associated_data, shared_secret) -> None:
    # When a connections is established, the client generates a public key
    # and sends it over to the server. The server then uses this key, along
    # with the shared secret that was derived from the password, to create
    # a Double Ratchet object on the server side associated said client,
    # and an encrypted initial message. This encrypted initial message is
    # then sent to the client were it is decrypted in order to generate the
    # client-side Double Ratchet object that is synced with server's.

    ratchet_public = X448PublicKey.from_public_bytes(client.connection.recv(2048))
    
    initial_message = bytes("Welcome to the Double-Ratchet messenger.", "utf-8")

    server_double_ratchet, initial_message_encrypted = await DoubleRatchet.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=ratchet_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ),
        message=initial_message,
        associated_data=associated_data,
        **dr_configuration
    )

    client.double_ratchet = server_double_ratchet

    client.send_encrypted_message(initial_message_encrypted)

    await client.send_message(bytes(str(len(clients)) + " user(s) connected\n", "utf-8"), associated_data)

    connected_message = client.address[0] + " connected, " + str(len(clients)) + " user(s) connected\n"
    print(connected_message)
    await broadcast(clients, client, bytes(connected_message, "utf-8"), associated_data)

    # Now that the server created a Double Ratchet synced with a particular
    # client, the server will begin listening for incoming messages. When
    # a message is found, the Double Ratchet is used to encrypt the message 
    # before it is sent to every other connected client.

    exit_client = False
    while not exit_client:
        try:
            encrypted_message_stream = client.connection.recv(2048)
            if encrypted_message_stream:
                encrypted_message = construct_encrypted_message(encrypted_message_stream)
                decrypted_message = await client.get_decrypted_message(encrypted_message, associated_data)
    
                if str(decrypted_message, "utf-8") == "EXIT":
                    await remove_client(clients, client, associated_data)
                    exit_client = True
                    break

                print("Enc:", encrypted_message.ciphertext)
                print("Dec:", str(decrypted_message, "utf-8"))

                await broadcast(clients, client, decrypted_message, associated_data)
            else:
                await remove_client(clients, client, associated_data)
        except:
            continue


async def broadcast(clients: List[Client], message_author: Client, message: bytes, associated_data: bytes) -> None:
    for client in clients:
        if message_author == None or client is not message_author:
            try:
                await client.send_message(message, associated_data)
            except:
                remove_client(clients, client, associated_data)


async def remove_client(clients: List[Client], to_remove: Client, associated_data: bytes) -> None:
    to_remove.connection.close()
    if to_remove in clients:
        clients.remove(to_remove)
    disconnected_message = to_remove.address[0] + " disconnected, " + str(len(clients)) + " user(s) connected\n"
    print(disconnected_message)
    await broadcast(clients, None, bytes(disconnected_message, "utf-8"), associated_data)
    

def construct_encrypted_message(encrypted_message_stream: bytes) -> EncryptedMessage:
    ratchet_pub = encrypted_message_stream[0:56]
    previous_sending_chain_length = int.from_bytes(encrypted_message_stream[56:66], "big")
    sending_chain_length = int.from_bytes(encrypted_message_stream[66:76], "big")
    ciphertext = encrypted_message_stream[76:]
    return EncryptedMessage(
        Header(
            ratchet_pub, 
            previous_sending_chain_length, 
            sending_chain_length), 
        ciphertext
    )


if __name__ == "__main__":
    main()