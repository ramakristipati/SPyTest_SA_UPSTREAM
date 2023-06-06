import pickle
import socket

def ospf_init():
    #s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    #s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    s.bind(('0.0.0.0', 0))
    #s.bind(('0.0.0.0'))
    #s.bind(('',0x0800))
    #s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    #s.ioctl(socket.SIO_RCVALL, 1)
    return s

def ospf_poll(s, timeout):

    before = time.time()
    rfds, _, _ = select.select([s], [], [], timeout)
    after = time.time()
    elapsed = after - before
    msg = s.recv(8*1024) if rfds else ""
    return elapsed, msg

def ospf():

    s = ospf_init()
    while True:
        elapsed, msg = ospf_poll(s, 30)
        if msg:
            packet = pickle.loads(msg)
            print(packet)

from socket import AF_INET, IPPROTO_IP, IP_HDRINCL, RCVALL_ON, SIO_RCVALL, SOCK_RAW, getfqdn, gethostbyname, gethostname, select, time
import struct
import binascii

local_name = getfqdn(gethostname())
local_addr = gethostbyname(local_name)
sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP)

sniffer.bind((local_addr, 0))
sniffer.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

sniffer.ioctl(SIO_RCVALL, RCVALL_ON)

while True:
    pkt = sniffer.recvfrom(2048)

    ipHeader = pkt[0][0:20]
    ip_hdr = struct.unpack("!9s1s10s",ipHeader)
    print("proto:", binascii.hexlify(ip_hdr[1]))
ospf()
