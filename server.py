from socket import *
from socket import socket, AF_PACKET, SOCK_RAW
import binascii
import struct

SOCKET = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))

def handleIPv4(frame):
    ipHeader = frame[0][14:34]
    ip_hdr = struct.unpack('!BBHHHBBH4s4s' , ipHeader)

    print("IPv4")

    protocol = ip_hdr[6]
    source_address = inet_ntoa(ip_hdr[8])
    destination_address = inet_ntoa(ip_hdr[9])

    if protocol == 6:
        print("TCP")
    elif protocol == 17:
        print("UDP")
    elif protocol == 1:
        print("ICMP")
    else:
        print("Other transport protocol code (%d)" % protocol)

    print ("Source IP address %s" % source_address) # network to ascii convertion
    print ("Destination IP address %s" % destination_address) # network to ascii convertion

def handleIPv6(frame):
    ipHeader = frame[0][14:54]
    ip_hdr = struct.unpack('!IHBB16s16s' , ipHeader)

    print("IPv6")
    
    protocol = ip_hdr[3]
    source_address = inet_ntop(ip_hdr[4])
    destination_address = inet_ntop(ip_hdr[5])

    print(protocol)
    print(source_address)
    print(destination_address)

    if protocol == 6:
        print("TCP")
    elif protocol == 17:
        print("UDP")
    elif protocol == 1:
        print("ICMP")
    else:
        print("Other transport protocol code (%d)" % protocol)

    print ("Source IP address %s" % source_address) # network to ascii convertion
    print ("Destination IP address %s" % destination_address) # network to ascii convertion

def main():
    while True:
        print('-')
        frame = SOCKET.recvfrom(2048)
        eHeader = frame[0][0:14]
        eth_hdr = struct.unpack("!6s6sH", eHeader)
        dstMac = binascii.hexlify(eth_hdr[0]) 
        srcMac = binascii.hexlify(eth_hdr[1]) 
        ipType = hex(eth_hdr[2])

        if (ipType == '0x800'):
            handleIPv4(frame)
        elif (ipType == '0x86dd'):
            handleIPv6(frame)
        

        # ipHeader = frame[0][14:34]
        # ip_hdr = struct.unpack('!BBHHHBBH4s4s' , ipHeader)
        # version_ihl = ip_hdr[0]
        # version = version_ihl >> 4
        
        # if version == 4:
        #     print("IPv4")
        #     protocol = ip_hdr[6]

        #     source_address = inet_ntoa(ip_hdr[8])
        #     destination_address = inet_ntoa(ip_hdr[9])

        #     if protocol == 6:
        #         print("TCP")
        #     elif protocol == 17:
        #         print("UDP")
        #     elif protocol == 1:
        #         print("ICMP")
        #     else:
        #         print("Other transport protocol code (%d)" % protocol)
        #     print ("Source IP address %s" % source_address) # network to ascii convertion
        #     print ("Destination IP address %s" % destination_address) # network to ascii convertion
        # elif version == 6:
        #     print("IPv6")
        #     print(ip_hdr[3])
        #     print(ip_hdr[5])
        
        #     source_address = inet_ntoa(ip_hdr[8])
        #     destination_address = inet_ntoa(ip_hdr[9])
            
        #     if protocol == 6:
        #         print("TCP")
        #     elif protocol == 17:
        #         print("UDP")
        #     elif protocol == 1:
        #         print("ICMP")
        #     else:
        #         print("Other transport protocol code (%d)" % protocol)
        #     print ("Source IP address %s" % source_address) # network to ascii convertion
        #     print ("Destination IP address %s" % destination_address) # network to ascii convertion
        #     next_headerIPv6(ip_hdr)
        # else:
        #     print("Other network protocol version (%d)" % version)


main()