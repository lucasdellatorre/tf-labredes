from socket import *
import binascii
import struct
import threading
import time

arp_request_count = 0
arp_reply_count = 0

ipv4_count = 0
ipv6_count = 0

icmpv6_count = 0

udp_count = 0
tcp_count = 0

icmp_count = 0

def flooding_checker():
    global arp_request_count, arp_reply_count, icmp_count, ipv4_count, ipv6_count, icmpv6_count, udp_count, tcp_count
    # print("OI")
    while True:
        time.sleep(2)  # Interval time for checking flooding (adjust as needed)
        
        print('==== Quantidade de pacotes ====')
        print(f"ARP request: {arp_request_count}")
        print(f"ARP repçy: {arp_reply_count}")
        print(f"ICMP: {icmp_count}")
        print(f"IPv4: {ipv4_count}")
        print(f"IPv6: {ipv6_count}")
        print(f"ICMPv6: {icmpv6_count}")
        print(f"UDP: {udp_count}")
        print(f"TCP: {tcp_count}")
        if arp_reply_count > arp_request_count * 3:
            print("== Arp Flooding detectado! ==")
        
        if icmp_count > 1000:
            print("== ICMP Flooding detectado! ==")
        print('=======================')


        arp_request_count = 0
        arp_reply_count = 0
        ipv4_count = 0
        ipv6_count = 0
        icmpv6_count = 0
        udp_count = 0
        tcp_count = 0
        icmp_count = 0

    
threading.Thread(target=flooding_checker).start()
server_socket = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
print("The server is ready to receive")
while True:
    # print('-')
    frame = server_socket.recvfrom(2048)
    eHeader = frame[0][0:14]
    eth_hdr = struct.unpack("!6s6s2s", eHeader)  # 6 dest MAC, 6 host MAC, 2 ethType

    dest_mac = binascii.hexlify(eth_hdr[0]).decode('utf-8')
    src_mac = binascii.hexlify(eth_hdr[1]).decode('utf-8')
    eth_type = binascii.hexlify(eth_hdr[2]).decode('utf-8')

    if eth_type == '0806':  # Check if the Ethernet type is ARP (0x0806)
        arp_data = frame[0][14:42]  # ARP data starts at byte 14 and ends at byte 42
        arp_hdr = struct.unpack('!HHBBH6s4s6s4s', arp_data)

        arp_operation = arp_hdr[4]
        source_mac = binascii.hexlify(arp_hdr[5]).decode('utf-8')
        source_ip = inet_ntoa(arp_hdr[6])
        target_mac = binascii.hexlify(arp_hdr[7]).decode('utf-8')
        target_ip = inet_ntoa(arp_hdr[8])

        # print("ARP Packet:")
        # print(f"Source MAC: {source_mac}")
        # print(f"Source IP: {source_ip}")
        # print(f"Target MAC: {target_mac}")
        # print(f"Target IP: {target_ip}")

        if arp_operation == 1:  # 1 is request, 2 is reply
            # print("ARP Request")
            arp_request_count += 1
        elif arp_operation == 2:
            # print("ARP Reply")
            arp_reply_count += 1
        # else:
        #     print("Unknown ARP Operation")       

    elif eth_type == '86dd':  # Check if the Ethernet type is IPv6 (0x86DD)
        ipv6_count += 1
        ipv6_header = frame[0][14:54]  # IPv6 header is 40 bytes (excluding Ethernet header)
        ip_hdr = struct.unpack('!IHBB16s16s', ipv6_header)

        version = ip_hdr[0] >> 28  # Get IPv6 version
        traffic_class = ip_hdr[0] >> 20 & 0xFF  # Get Traffic Class
        flow_label = ip_hdr[0] & 0xFFFFF  # Get Flow Label
        payload_length = ip_hdr[1]  # Payload Length
        next_header = ip_hdr[2]  # Next Header (identifies the upper-layer protocol)
        hop_limit = ip_hdr[3]  # Hop Limit
        source_address = inet_ntop(AF_INET6, ip_hdr[4])  # Source IPv6 Address
        destination_address = inet_ntop(AF_INET6, ip_hdr[5])  # Destination IPv6 Address

        # print("IPv6 Packet:")
        # print(f"Version: {version}")
        # print(f"Traffic Class: {traffic_class}")
        # print(f"Flow Label: {flow_label}")
        # print(f"Payload Length: {payload_length}")
        # print(f"Next Header: {next_header}")
        # print(f"Hop Limit: {hop_limit}")
        # print(f"Source IP address: {source_address}")
        # print(f"Destination IP address: {destination_address}")

        if next_header == 58:  # Check if the Next Header is ICMPv6 (58 for ICMPv6)
            icmpv6_data = frame[0][54:]  # Extract ICMPv6 data from the frame
            icmpv6_hdr = struct.unpack('!BBH', icmpv6_data[:4])

            icmpv6_type = icmpv6_hdr[0]
            icmpv6_code = icmpv6_hdr[1]
            icmpv6_checksum = icmpv6_hdr[2]

            # print("ICMPv6 Packet:")
            # print(f"Type: {icmpv6_type}")
            # print(f"Code: {icmpv6_code}")
            # print(f"Checksum: {icmpv6_checksum}")
            # Add handling for specific ICMPv6 types and codes as needed

    else:
        ipHeader = frame[0][14:34]
        ip_hdr = struct.unpack('!BBHHHBBH4s4s', ipHeader)
        version_ihl = ip_hdr[0]
        version = version_ihl >> 4
        protocol = ip_hdr[6]

        source_address = inet_ntoa(ip_hdr[8])
        destination_address = inet_ntoa(ip_hdr[9])

        # if version == 4:
        #     print("IPv4")
        # elif version == 6:
        #     print("IPv6")
        # else:
        #     print("Other network protocol version (%d)" % version)

        # print("Source IP address %s" % source_address)  # network to ascii conversion
        # print("Destination IP address %s" % destination_address)  # network to ascii conversion

        if protocol == 6:
            # print("TCP")
            tcp_count += 1
        elif protocol == 17:
            # print("UDP")
            udp_count += 1
        elif protocol == 1:
            # print("ICMP")
            if version == 6:
                icmpv6_count += 1
            icmp_count += 1
        # else:
        #     print("Other transport protocol code (%d)" % protocol)