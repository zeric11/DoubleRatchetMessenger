# Double Ratchet Messenger

A server-client chat application that encrypts messages according to the double ratchet algorithm.

## Requirements

This project was developed and tested using python 3.8 on Ubuntu 20.04.
The [DoubleRatchet]{https://github.com/Syndace/python-doubleratchet} package was used to implement the double ratchet algorithm, while sockets were used for messaging functionality.

Use the following command to install this application's requirements.

```
pip3 install -r requirements.txt
```

## Functionality

Use the following command to start the server passing in the IP address, port, and password.

```
python3 server.py [IP ADDRESS] [PORT] [PASSWORD]
```

To find your IP address, use the following command.

```
hostname -I
```

Once the server is running, a client can connect using the following command passing in the IP address, port, username, and password.

```
python3 client.py [IP ADDRESS] [PORT] [USERNAME] [PASSWORD]
```

It should be noted that the IP address, port, and password must match what was entered when booting the server.

Once connected, messages may be sent by simply entering text into the terminal.
A total of 10 clients may connect the server at a time.
When a user enters a message, the client uses the double ratchet to encrypt the message before being sent to the server.
Once the server receives this message and performs decryption, the message along with original encryption will be printed at the server side. 
This message is then re-encrypted before being broadcast to every other connected client.

## Demo

A few shell script files are provided to quickly demo this application.
Use the following commands on three separate terminal sessions to open a server and connect two clients: Alice and Bob.

Open server:
```
bash server_demo.sh
```

Connect Alice:
```
bash client_demo_Alice.sh
```

Connect Bob:
```
bash client_demo_Bob.sh
```

Once connected, ALice and Bob are able to send and receive encrypted messages from each other through the server.

