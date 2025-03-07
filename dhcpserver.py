#!/usr/bin/env python

import socket
import struct
from dhcppython.packet import DHCPPacket

# Configuration
SERVER_IP = '192.168.1.1'
OFFERED_IP = '192.168.1.100'
SUBNET_MASK = '255.255.255.0'
ROUTER_IP = '192.168.1.1'
DNS_SERVER_IP = '8.8.8.8'
SERVER_PORT = 67
CLIENT_PORT = 68

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', SERVER_PORT))

print("DHCP server started. Listening...")

while True:
    try:
        data, addr = sock.recvfrom(1024)
        packet = DHCPPacket.from_bytes(data)
        
        breakpoint()
        if packet.msg_type == DHCPPacket.DISCOVER:
            print("Received DHCP Discover from", addr)
            
            offer_packet = DHCPPacket.create_offer(
                xid=packet.xid,
                mac=packet.chaddr,
                ip=OFFERED_IP,
                server_ip=SERVER_IP,
                subnet_mask=SUBNET_MASK,
                router=ROUTER_IP,
                dns_server=DNS_SERVER_IP
            )
            sock.sendto(offer_packet.asbytes, (addr[0], CLIENT_PORT))
            print("Sent DHCP Offer to", addr)

        elif packet.msg_type == DHCPPacket.REQUEST:
             print("Received DHCP Request from", addr)

             ack_packet = DHCPPacket.create_ack(
                xid=packet.xid,
                mac=packet.chaddr,
                ip=OFFERED_IP,
                server_ip=SERVER_IP,
                subnet_mask=SUBNET_MASK,
                router=ROUTER_IP,
                dns_server=DNS_SERVER_IP
            )
             sock.sendto(ack_packet.asbytes, (addr[0], CLIENT_PORT))
             print("Sent DHCP ACK to", addr)

    except Exception as e:
        print("Error:", e)
