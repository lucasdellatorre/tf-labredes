from socket import *
from socket import socket, AF_PACKET, SOCK_RAW
import binascii
import struct

server_socket = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
print("The server is ready to receive")
while True:
    print('-')
    frame = server_socket.recvfrom(2048)
    eHeader = frame[0][0:14]
    eth_hdr = struct.unpack("!6s6s2s", eHeader) # 6 dest MAC, 6 host MAC, 2 ethType
    binascii.hexlify(eth_hdr[0])
    binascii.hexlify(eth_hdr[1])
    binascii.hexlify(eth_hdr[2])

    ipHeader = frame[0][14:34]
    ip_hdr = struct.unpack("!12s4s4s", ipHeader) # 12s represents Identification, Time to Live, Protocol | Flags, Fragment Offset, Header Chec
    print ("Source IP address %s" % inet_ntoa(ip_hdr[1])) # network to ascii convertion
    print ("Destination IP address %s" % inet_ntoa(ip_hdr[2])) # network to ascii convertion