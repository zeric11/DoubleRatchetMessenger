# Client side of messenger app

# The python-doubleratchet package was used to implement the Double Ratchet algorithm:
#   https://pypi.org/project/DoubleRatchet/
#   https://github.com/Syndace/python-doubleratchet

# pip3 install -r requirements.txt


from typing import Any, Dict,  List

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

async def main():
    if len(sys.argv) != 5:
        print("Correct usage: python3 client.py [IP ADDRESS] [PORT] [USERNAME] [PASSWORD]")
        return
    
    ip_address = str(sys.argv[1])
    port = int(sys.argv[2])
    username = str(sys.argv[3])
    password = str(sys.argv[4])

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
    server.connect((ip_address, port))

    # When the client connects to the server, it first generates a private
    # key, and from that, a public key that is sent to the server. Once the
    # server uses that key to create its Double Ratchet object, the server
    # will sent the client the encrypted initial message that results from 
    # generating the Double Ratchet. Using the encrypted initial message, 
    # along with the shared secret that was derived from the password, the
    # client creates a Double Ratchet object that is synced with the server's.

    ratchet_private = X448PrivateKey.generate()
    ratchet_public = ratchet_private.public_key()

    server.send(ratchet_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    
    initial_message_received = False
    encrypted_message_stream = None
    while not initial_message_received:
        sockets_list = [sys.stdin, server]
        read_sockets, write_socket, error_socket = select.select(sockets_list, [], [])

        for read_socket in read_sockets:
            if read_socket == server:
                encrypted_message_stream = read_socket.recv(2048)
                initial_message_received = True

    initial_message_encrypted = construct_encrypted_message(encrypted_message_stream)

    client_double_ratchet, initial_message_decrypted = await DoubleRatchet.decrypt_initial_message(
        shared_secret=shared_secret,
        own_ratchet_priv=ratchet_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        message=initial_message_encrypted,
        associated_data=associated_data,
        **dr_configuration
    )

    print(str(initial_message_decrypted, "utf-8") + "\n")
    
    # Now that the client is connected and the Double Ratchet is synced
    # with the server, the client will listen for messages. If a message
    # is coming from the server, then the client will need to decrypt
    # the message using the Double Ratchet, and print the result. If a 
    # message is coming from stdin (i.e. the client-side user input), then
    # the client will need to encrypt the message using the Double Ratchet,
    # and send the encrypted message to the server.

    exit_client = False
    while not exit_client:
        sockets_list = [sys.stdin, server]
        read_sockets, write_socket, error_socket = select.select(sockets_list, [], [])
    
        for read_socket in read_sockets:
            if read_socket == server:
                encrypted_message_stream = read_socket.recv(2048)
                encrypted_message = construct_encrypted_message(encrypted_message_stream)
                decrypted_message = await client_double_ratchet.decrypt_message(encrypted_message, associated_data)
                print(str(decrypted_message, "utf-8"))
            else:
                message = sys.stdin.readline()
                if message == "EXIT\n":
                    encrypted_message = await client_double_ratchet.encrypt_message(
                        bytes("EXIT", "utf-8"), 
                        associated_data
                    )
                    send_encrypted_message(encrypted_message, server)
                    exit_client = True
                    break
                else:
                    encrypted_message = await client_double_ratchet.encrypt_message(
                        bytes("[" + username + "]: " + message, "utf-8"), 
                        associated_data
                    )
                    send_encrypted_message(encrypted_message, server)
                    sys.stdout.write("[You]: " + message + "\n")
                    sys.stdout.flush()

    server.close()


def extend_to_32_char(message: str) -> str:
    message += " " * (32 - len(message))
    return message


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


def send_encrypted_message(encrypted_message: EncryptedMessage, server) -> None:
    to_send = encrypted_message.header.ratchet_pub  # len == 56
    to_send += encrypted_message.header.previous_sending_chain_length.to_bytes(10, "big")
    to_send += encrypted_message.header.sending_chain_length.to_bytes(10, "big")
    to_send += encrypted_message.ciphertext
    server.send(to_send)


if __name__ == "__main__":
    asyncio.run(main())