# Client side of messenger app


import socket
import select
import sys


def main():
    if len(sys.argv) != 3:
        print("Must provide IP Address and Port Number")
        return
    
    ip_address = str(sys.argv[1])
    port = int(sys.argv[2])

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #server.connect((ip_address, port))
    server.connect(("0.0.0.0", 6677)) 
    
    while True:
        sockets_list = [sys.stdin, server]
        read_sockets, write_socket, error_socket = select.select(sockets_list, [], [])
    
        for read_socket in read_sockets:
            if read_socket == server:
                message = read_socket.recv(2048)
                print(message)
            else:
                message = sys.stdin.readline()
                server.send(bytes(message, "utf-8"))
                sys.stdout.write("<You>")
                sys.stdout.write(message)
                sys.stdout.flush()

    server.close()


if __name__ == "__main__":
    main()