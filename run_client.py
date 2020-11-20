import socket
import ssl
import sys

sys.path.insert(0, '/home/pi/trustworthy_computing/src')

import config
from client import Client

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a socket object
s = ssl.wrap_socket(s)  # wrap socket to secure connection

s.connect(('192.168.1.25', 8080))  # connect to sever

client = Client(s)  # create new client object
client.handle_connection()  # handle connection with server
