# Server side of messenger app

# The python-doubleratchet package was used to implement the Double Ratchet algorithm:
#   https://pypi.org/project/DoubleRatchet/
#   https://github.com/Syndace/python-doubleratchet

# The python rsa package used to implement the rsa algorithm:
#   https://pypi.org/project/rsa/
#   https://www.section.io/engineering-education/rsa-encryption-and-decryption-in-python/

# The python TwoFish package used to implement the TwoFish algorithm:
#   https://pypi.org/project/twofish/

# pip3 install DoubleRatchet

# pip install rsa

# pip install twofish

# ***To do***
# The sockets are not communicating properly at the moment. Need to read into this: 
#    https://stackoverflow.com/questions/48506460/python-simple-socket-client-server-using-asyncio

# Encryption seems to be working, but without the sockets communicating, 
# we cannot yet test decryption.

# When the clients join the chat, the program needs to be altered so that
# the DoubleRatchet object for each client is created at the same time
# instead of separately.


from typing import Any, Dict

import asyncio
import socket
import sys
import threading
import rsa

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
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

# The following is python-rsa
#===============================================================

class RSA(rsa):
    def generateKeys():
        (publicKey, PrivateKey) = rsa.newkeys(1024)
        with open('keys/publicKey.pem', 'wb') as p:
            p.write(publicKey.save_pkcs1('PEM'))
        with open('keys/privateKey.pem', 'wb') as p:
            p.write(PrivateKey.save_pkcs1('PEM'))

    def loadKeys():
        with open('keys/publicKey.pem', 'rb') as p:
            publicKey = rsa.PublicKey.load_pkcs1(p.read())
        with open('keys/privateKey.pem', 'rb') as p:
            privateKey = rsa.PrivateKey.load_pkcs1(p.read())
        return privateKey, publicKey

    def encrypt(message, key):
        return rsa.encrypt(message.encode('ascii'), key)

    def decrypt(ciphertext, key):
        try:
            return rsa.decrypt(ciphertext, key).decode('ascii')
        except:
            return False
        
    def sign(message, key):
            return rsa.sign(message.encode('ascii'), key, 'SHA-256')

    def verify(message, signature, key):
        try:
            return rsa.verify(message.encode('ascii'), signature, key,) == 'SHA-256'
        except:
            return False
    
# Messenger functionality starts here:
#===============================================================

async def main():
    if len(sys.argv) != 3:
        print("Must provide IP Address and Port Number")
        return
    
    ip_address = str(sys.argv[1])
    port = int(sys.argv[2])

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    #server.bind((ip_address, port))
    server.bind(("0.0.0.0", 6677)) 
    server.listen(2)

    associated_data = "Some Associated Data".encode("ASCII")
    shared_secret = "This is supposed to be 32 bytes.".encode("ASCII")

    clients = []
    threads = []
    while len(threads) < 2:
        connection, address = server.accept()
        clients.append(connection)
        print(address[0] + " connected")
        '''
        new_client_thread = threading.Thread(
            target=client_thread, 
            args=(server, clients, connection, address, associated_data, shared_secret)
        )
        new_client_thread.start()
        '''
        threads.append(asyncio.create_task(client_thread(
            server, 
            clients, 
            connection, 
            address, 
            associated_data, 
            shared_secret
        )))
        
    await asyncio.wait(threads)

    server.close()

# Variable to change encryption type
cryptType = 1 

# RSA Implementation 
if(cryptType == 2):
    async def clinet_thread(server, clients, connection, address, associated_data, shared_secret) -> None:
        connection.send(bytes("You are connected.", "utf-8"))


# Double Ratchet Implementation
if(cryptType == 1):
    async def client_thread(server, clients, connection, address, associated_data, shared_secret) -> None:
        connection.send(bytes("You are connected.", "utf-8"))

        ratchet_private = X448PrivateKey.generate()
        ratchet_public = ratchet_private.public_key()

        initial_message = "This is the initial message.".encode("UTF-8")

        _, initial_message_encrypted = await DoubleRatchet.encrypt_initial_message(
            shared_secret=shared_secret,
            recipient_ratchet_pub=ratchet_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            message=initial_message,
            associated_data=associated_data,
            **dr_configuration
        )

        double_ratchet, initial_message_decrypted = await DoubleRatchet.decrypt_initial_message(
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

        assert initial_message == initial_message_decrypted


        while True:
            try:
                message_tosend = connection.recv(2048)
                if message_tosend:
                    to_send = "[" + address[0] + "] " + str(message_tosend)
                    encrypted_message = double_ratchet.encrypt_message(
                        to_send.encode("UTF-8"), 
                        associated_data
                    )
                    print(to_send, "Enc:", encrypted_message)
                    broadcast(clients, connection, encrypted_message)
                else:
                    if connection in clients:
                        clients.remove(connection)
            except:
                continue


def broadcast(clients, connection, message) -> None:
    for client in clients:
        if client != connection:
            try:
                client.send(message)
            except:
                client.close()
                if connection in clients:
                    clients.remove(connection)


if __name__ == "__main__":
    asyncio.run(main())