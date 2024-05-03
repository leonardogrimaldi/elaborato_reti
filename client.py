import socket, os, struct
from sys import getsizeof
from bitstring import BitArray

# ICMP types
TYPE_ECHO_REPLY = 0
TYPE_ECHO_REQUEST = 8
# ICMP codes
CODE_ECHO_REPLY = 0
CODE_ECHO_REQUEST = 0
DATA = "hi HUMANS!" # UTF-8

def printICMP(packet):
    print(packet)
    print("Type " + packet[:8])
    print("Code " + packet[8:16])
    print("Checksum " + packet[16:32])
    print("Identifier " + packet[32:48])
    print("Sequence number " + packet[48:64])
    print("Data: " + packet[64:])
def ICMPchecksum(packet):
    bitArr = BitArray(bytes=packet)
def ping(mySocket, destinationHost, identifier, sequenceNumber):
    type = TYPE_ECHO_REQUEST
    code = CODE_ECHO_REQUEST
    checksum = 0
    data = DATA

    header = struct.pack('!BBHHH', type, code, checksum, identifier, sequenceNumber) # Spiegare nel PDF cosa fa?
    # len(data) Ci dà il numero di caratteri nella stringa
    # struct.pack('!10s', ...) dice quindi di usare 10 byte 
    data = struct.pack('!' + str(len(data)) + 's', data.encode()) # encode() uses UTF-8 encoding by default.
    packet = header + data

    #bitArr = BitArray(bytes=packet)
    #ICMPchecksum(packet)
    #printICMP(bitArr.bin)

    destIP = socket.gethostbyname(destinationHost)  # traduce l'hostname in IP
    print(destIP)
    bytesSent = mySocket.sendto(packet, (destIP, 1))
    print("ICMP bytes sent: ", bytesSent)
def main():
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    myID = os.getpid()
    for i in range(4):
        print(i)
        ping(mySocket, "google.com",myID, i)
    

main()

    
