#!/usr/bin/env python

# example invocation:
#   sudo -E ./dhcpserver2.py eth0 192.168.1.55

# recall:
#    DISCOVER ->
# <- OFFER
#    REQUEST  ->
# <- ACK      ->
import os
import sys

from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

def handle_packet(packet, iface, offer_ip):
    #print(f'handle_packet({packet}, {iface})')

    our_mac = get_if_hwaddr(iface)
    src_mac = packet[Ether].src

    server_ip = offer_ip[0:offer_ip.rfind('.')] + '.1'

    if 0:
        print(f'  server ip: {server_ip}')
        print(f' server mac: {our_mac}')
        print(f' client mac: {src_mac}')
        print(f'offering ip: {offer_ip}')

    if DHCP in packet and packet[DHCP].options[0][1] == 1: # DHCP Discover
        xid = packet[BOOTP].xid

        print(f'Received DHCP Discover from: {packet[Ether].src} with transaction id: {xid}')

        if our_mac == src_mac:
            print('WARNING! Received DHCP Discover from your own interface! Bailing!')
            return

        options = []
        options.append(('message-type', 'offer'))
        options.append(('server_id', server_ip))
        options.append(('lease_time', 600))
        options.append(('subnet_mask', '255.255.255.0'))
        options.append(('router', server_ip))
        options.append(('name_server', server_ip))
        options.append('end')

        # Craft DHCP Offer
        dhcp_offer = Ether(src=our_mac, dst=src_mac)/ \
                     IP(src=server_ip, dst=offer_ip)/ \
                     UDP(sport=67, dport=68)/ \
                     BOOTP(op=2, yiaddr=offer_ip, siaddr=server_ip, giaddr="0.0.0.0", chaddr=packet[BOOTP].chaddr, xid=xid)/ \
                     DHCP(options=options)
        
        print(dhcp_offer)
        sendp(dhcp_offer, iface=iface, verbose=False)
        print("Sent DHCP Offer to: " + packet[Ether].src)

    elif DHCP in packet and packet[DHCP].options[0][1] == 3: # DHCP Request
        xid = packet[BOOTP].xid

        print("Received DHCP Request from: " + packet[Ether].src)

        # Craft DHCP ACK
        dhcp_ack = Ether(src=our_mac, dst=src_mac)/ \
                   IP(src=server_ip, dst=server_ip)/ \
                   UDP(sport=67, dport=68)/ \
                   BOOTP(op=2, yiaddr=server_ip, siaddr=server_ip, giaddr="0.0.0.0", chaddr=packet[BOOTP].chaddr, xid=xid)/ \
                   DHCP(options=[("message-type","ack"), ("server_id",server_ip), ("subnet_mask","255.255.255.0"), ("router",server_ip), 'end'])
        
        sendp(dhcp_ack, iface=iface, verbose=False)
        print("Sent DHCP ACK to: " + packet[Ether].src)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('USAGE: {sys.argv[0]} <interface> <ip>')
        print('WHERE:')
        print('  <interface> is which interface to service')
        print('         <ip> is what IP to offer')
        sys.exit(-1)

    ifname, offer_ip = sys.argv[1], sys.argv[2]

    # Sniff DHCP packets
    print(f'listening on interface: {ifname}')
    filter = 'udp and (port 67 or port 68)'
    sniff(  iface=ifname,
            filter='udp and (port 67 or port 68)',
            prn=lambda packet: handle_packet(packet, ifname, offer_ip)
        )
