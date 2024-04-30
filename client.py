import socket

# ICMP types
ECHO_REPLY = 0
ECHO = 8 
def ping(destinationHost):
    type = ECHO_REPLY
    
