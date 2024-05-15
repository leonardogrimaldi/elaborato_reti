import socket, os, struct, time, select

ICMP_MAX_RECV = 2048
# ICMP types
TYPE_ECHO_REPLY = 0
TYPE_ECHO_REQUEST = 8
# ICMP codes
CODE_ECHO_REPLY = 0
CODE_ECHO_REQUEST = 0
DATA = "Buongiorno mondo!" # UTF-8

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
    header = struct.pack('!BBHHH', TYPE_ECHO_REQUEST, CODE_ECHO_REQUEST, checksum, identifier, sequenceNumber)
    # len(data) Ci dà il numero di caratteri nella stringa
    # esempio: len(data) = 10
    # struct.pack('!10s', ...) dice quindi di usare 10 byte
    # encode() usa l'encoding UTF-8 di default.
    data = struct.pack('!' + str(len(DATA)) + 's', DATA.encode())
    packet = header + data
    # Calcolo il checksum del pacchetto
    chk = ICMPchecksum(packet)
    # Creo l'header con il nuovo checksum
    header = struct.pack('!BBHHH', TYPE_ECHO_REQUEST, CODE_ECHO_REQUEST, chk, identifier, sequenceNumber)
    # Ricostruisco il pacchetto
    packet = header + data
    try:
        destIP = socket.gethostbyname(destinationHost)  # traduce l'hostname in IP oppure se è già IP lo lascia invariato
    except:
        raise ValueError("Non è stato possibile trovare l'IP del hostname inserito")
    else:
        sentTime = time.time()
        try:
            bytesSent = mySocket.sendto(packet, (destIP, 1))
        except socket.error:
            raise socket.error
        return bytesSent, sentTime
def receive_reply(mySocket, myID, timeout):
    timeLeft = timeout
    while True:
        startedSelect = time.time()
        # aspetto che il 'mySocket' sia in stato read ovvero ricezione pachetti
        readable, writeable, exceptional = select.select([mySocket], [], [], timeout)
        selectTime = (time.time() - startedSelect)
        # select timeout
        if not (readable or writeable or exceptional):
            return None, None, None, None, None 
        timeReceived = time.time()
        packet, address = mySocket.recvfrom(ICMP_MAX_RECV)
        ipHeader = packet[:20]
        (iphVersion, iphTypeOfSvc, iphLength, iphID, iphFlags, iphTTL,
         iphProtocol, iphChecksum, iphSrcIP, iphDestIP) = struct.unpack("!BBHHHBBHII", ipHeader)
        icmpHeader = packet[20:28]
        icmpType, icmpCode, icmpChecksum, \
        icmpPacketID, icmpSeqNumber = struct.unpack("!BBHHH", icmpHeader)
        if icmpPacketID == myID: # Nostro pacchetto
            dataSize = len(packet) - 28
            return timeReceived, dataSize, iphSrcIP, icmpSeqNumber, iphTTL
        timeLeft = timeLeft - selectTime
        if timeLeft <= 0:
            return None, None, None, None, None
def do_one(hostName, myID, seqNumber, timeout):
    try:
        mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
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
        times = 4   # quante volte eseguire ping sullo stesso hostName
        for i in range(times):
            do_one(hostName, myID, i, timeout)
main()