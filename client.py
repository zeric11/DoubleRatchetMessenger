#client
#Ref: https://python-socketio.readthedocs.io/en/latest/intro.html#:~:text=Socket.IO%20is%20a%20transport,components%20are%20written%20in%20JavaScript.
import socketio

url = 'http://localhost:8080'

message = 'testing'

sio = socketio.Client()

sio.connect(url)

@sio.event
def connect(): 
    print('Connected to localhost 8080')

@sio.on('received message')
def on_received():
    print('message received')

sio.emit('send message', message)