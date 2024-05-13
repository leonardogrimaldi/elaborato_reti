import socket, os, struct, time, select

ICMP_MAX_RECV = 2048
# ICMP types
TYPE_ECHO_REPLY = 0
TYPE_ECHO_REQUEST = 8
# ICMP codes
CODE_ECHO_REPLY = 0
CODE_ECHO_REQUEST = 0
DATA = "Buongiorno mondo!" # UTF-8

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
    overflow = sum >> 16
    checksum = ~(sum + overflow) & 0xFFFF
    return checksum

def ping(mySocket, destinationHost, identifier, sequenceNumber):
    checksum = 0
    # Spiegare nel PDF cosa fa?
    header = struct.pack('!BBHHH', TYPE_ECHO_REQUEST, CODE_ECHO_REQUEST, checksum, identifier, sequenceNumber)
    # len(data) Ci dà il numero di caratteri nella stringa
    # struct.pack('!10s', ...) dice quindi di usare 10 byte 
    data = struct.pack('!' + str(len(DATA)) + 's', DATA.encode()) # encode() uses UTF-8 encoding by default.
    packet = header + data
    chk = ICMPchecksum(packet)
    header = struct.pack('!BBHHH', TYPE_ECHO_REQUEST, CODE_ECHO_REQUEST, chk, identifier, sequenceNumber)
    packet = header + data
    try:
        destIP = socket.gethostbyname(destinationHost)  # traduce l'hostname in IP
    except:
        raise ValueError("Non è stato possibile trovare l'IP del hostname inserito")
    else:
        sentTime = time.time()
        try:
            bytesSent = mySocket.sendto(packet, (destIP, 1))
        except socket.error as e:
            print("Errore socket", e)
            raise socket.error
        return bytesSent, sentTime
# Timeout is in seconds
def receive_reply(mySocket, myID, timeout):
    timeLeft = timeout
    while True:
        startedSelect = time.time()
        # aspetto che il 'mySocket' sia in stato read ovvero ricezione pachetti
        readable, writeable, exceptional = select.select([mySocket], [], [], timeout)
        selectTime = (time.time() - startedSelect)
        # select timeout case
        if not (readable or writeable or exceptional):
            return None, None, None, None, None 
        timeReceived = time.time()
        packet, address = mySocket.recvfrom(ICMP_MAX_RECV)
        ipHeader = packet[:20]
        (iphVersion, iphTypeOfSvc, iphLength, iphID, iphFlags, iphTTL,
         iphProtocol, iphChecksum, iphSrcIP, iphDestIP) = struct.unpack("!BBHHHBBHII", ipHeader)
        icmpHeader = packet[20:28]
        icmpType, icmpCode, icmpChecksum, \
        icmpPacketID, icmpSeqNumber = struct.unpack(
            "!BBHHH", icmpHeader
        )
        if icmpPacketID == myID: # Our packet
            dataSize = len(packet) - 28
            return timeReceived, dataSize, iphSrcIP, icmpSeqNumber, iphTTL
        timeLeft = timeLeft - selectTime
        if timeLeft <= 0:
            return None, None, None, None, None
def do_one(hostName, myID, seqNumber, timeout):
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    try:
        bytesSent, sentTime = ping(mySocket, hostName, myID, seqNumber)
    except (ValueError, socket.error) as e:
        print("Pacchetto non inviato.", e)
    else:  
        print("Byte ICMP inviati: ", bytesSent)
        timeReceived, dataSize, iphSrcIP, icmpSeqNumber, iphTTL = receive_reply(mySocket, myID, timeout)
        mySocket.close()
        if timeReceived is not None:
            delay = (timeReceived - sentTime) * 1000
            print("%d byte da %s: icmp_seq=%d ttl=%d tempo=%d ms" % (
                dataSize, socket.inet_ntoa(struct.pack("!I", iphSrcIP)), icmpSeqNumber, iphTTL, delay)
            )
def main():
    while True:
        hostName = input("Inserisci l'indirizzo IP o hostname del destinatario.\n")
        timeout = 5 # secondi
        myID = os.getpid() & 0xFFFF  # tronca a 16 bit
        times = 4   # quante volte eseguire ping
        for i in range(times):
            do_one(hostName, myID, i, timeout)
main()