# Server side of messenger app

import socket
import sys
import threading


def main():
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
    server.listen(10)

    clients = []
    while True:
        connection, address = server.accept()
        clients.append(connection)
        print(address[0] + " connected")
        new_client_thread = threading.Thread(target=client_thread, args=(server, clients, connection, address))
        new_client_thread.start()

    server.close()


def client_thread(server, clients, connection, address) -> None:
    connection.send(bytes("You are connected.", "utf-8"))

    while True:
        try:
            message = connection.recv(2048)
            if message:
                to_send = "[" + address[0] + "] " + str(message)
                print(to_send)
                #socket.broadcast(to_print, connection)
                broadcast(clients,connection, to_send)

            else:
                remove(connection)
        
        except:
            continue


def broadcast(clients, connection, message) -> None:
    for client in clients:
        if client != connection:
            try:
                client.send(message)
            
            except:
                client.close()
                remove(client)


def remove(clients, connection) -> None:
    if connection in clients:
        clients.remove(connection)


if __name__ == "__main__":
    main()