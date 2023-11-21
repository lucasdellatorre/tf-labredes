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
    ip_hdr = struct.unpack('!BBHHHBBH4s4s' , ipHeader)
    version_ihl = ip_hdr[0]
    version = version_ihl >> 4
    protocol = ip_hdr[6]

    source_address = inet_ntoa(ip_hdr[8])
    destination_address = inet_ntoa(ip_hdr[9])
    
    if version == 4:
        print("IPv4")
    elif version == 6:
        print("IPv6")
    else:
        print("Other network protocol version (%d)" % version)

    print ("Source IP address %s" % source_address) # network to ascii convertion
    print ("Destination IP address %s" % destination_address) # network to ascii convertion

    if protocol == 6:
        print("TCP")
    elif protocol == 17:
        print("UDP")
    elif protocol == 1:
        print("ICMP")
    else:
        print("Other transport protocol code (%d)" % protocol)