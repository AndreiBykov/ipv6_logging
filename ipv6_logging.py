#!/usr/bin/python
from bcc import BPF

import sys
import socket
import os

from sys import argv

#arguments
interface="eth0"

if len(argv) == 3:
    if str(argv[1]) == '-i':
        interface = argv[2]

print("USAGE: %s [-i <if_name>]" % argv[0])
print ("binding socket to '%s'" % interface)	
 

bpf = BPF(src_file = "ipv6_filter.c", debug = 0)

function_tcp_filter = bpf.load_func("ipv6_filter", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_tcp_filter, interface)

socket_fd = function_tcp_filter.sock

sock = socket.fromfd(socket_fd, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)

sock.setblocking(True)

ETH_HLEN = 14 #Ethernet header length in bytes
IPV6_ADDR_SHIFT = 8 #Shift of addresses in IPv6 header

while 1:
    packet_str = os.read(socket_fd, 2048)
    
    packet_bytearray = bytearray(packet_str)

    src_host_ip = packet_bytearray[ETH_HLEN + IPV6_ADDR_SHIFT : ETH_HLEN + IPV6_ADDR_SHIFT + 16] 
    dst_host_ip = packet_bytearray[ETH_HLEN + IPV6_ADDR_SHIFT + 16: ETH_HLEN + IPV6_ADDR_SHIFT + 32]

    src_host_ip = []
    dst_host_ip = []

    for i in range(ETH_HLEN + IPV6_ADDR_SHIFT, ETH_HLEN + IPV6_ADDR_SHIFT + 16, 2):
	src_host_ip.append(packet_bytearray[i] * 256 + packet_bytearray[i + 1])

    for i in range(ETH_HLEN + IPV6_ADDR_SHIFT + 16, ETH_HLEN + IPV6_ADDR_SHIFT + 32, 2):
        dst_host_ip.append(packet_bytearray[i] * 256 + packet_bytearray[i + 1])

    src_str = ':'.join(hex(x)[2:] for x in src_host_ip)
    dst_str = ':'.join(hex(x)[2:] for x in dst_host_ip)

    msg = "Src host: " + src_str + "   Dest host: "+ dst_str

    print (msg)
