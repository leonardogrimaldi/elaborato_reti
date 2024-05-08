import socket, os, struct

# ICMP types
TYPE_ECHO_REPLY = 0
TYPE_ECHO_REQUEST = 8
# ICMP codes
CODE_ECHO_REPLY = 0
CODE_ECHO_REQUEST = 0
DATA = "!!" # UTF-8

def printICMP(packet):
    print(packet)
    print("Type ", packet[0])
    print("Code ", packet[1])
    print("Checksum ", packet[2:4])
    print("Identifier ", packet[4:6])
    print("Sequence number ", packet[6:8])
    print("Data: ", packet[8:])
def ICMPchecksum(packet):
    temp = packet
    if len(temp) % 2 != 0:
        temp += bytes([0])
    first = int.from_bytes(temp[0:2], byteorder='big')
    sum = first
    for i in range(2, len(temp) - 1, 2):
        next = int.from_bytes(temp[i:i+2],byteorder='big')
        sum += next
    checksum = ~sum & 0xFFFF
    return checksum

def ping(mySocket, destinationHost, identifier, sequenceNumber):
    checksum = 0
    header = struct.pack('!BBHHH', TYPE_ECHO_REQUEST, CODE_ECHO_REQUEST, checksum, identifier, sequenceNumber) # Spiegare nel PDF cosa fa?
    # len(data) Ci dà il numero di caratteri nella stringa
    # struct.pack('!10s', ...) dice quindi di usare 10 byte 
    data = struct.pack('!' + str(len(DATA)) + 's', DATA.encode()) # encode() uses UTF-8 encoding by default.
    packet = header + data
    chk = ICMPchecksum(packet)
    header = struct.pack('!BBHHH', TYPE_ECHO_REQUEST, CODE_ECHO_REQUEST, chk, identifier, sequenceNumber)
    packet = header + data 
    destIP = socket.gethostbyname(destinationHost)  # traduce l'hostname in IP
    print(destIP)
    bytesSent = mySocket.sendto(packet, (destIP, 1))
    print("ICMP bytes sent: ", bytesSent)
def main():
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    myID = os.getpid() & 0xFFFF  # tronca a 16 bit
    print("my ID:", myID)
    for i in range(4):
        print(i)
        ping(mySocket, "google.com",myID, i)

main()

    
