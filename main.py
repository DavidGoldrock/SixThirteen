import socket
from scapy.sendrecv import *
from scapy.layers.dns import *
import sys


def server():
    S = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    S.bind(('127.0.0.1', 20001))

    while True:

        print(chr(S.recvfrom(1024)[1][1]), end='')


def client():
    i = input("TEXT ")
    for l in i:
        packet = IP(dst="127.0.0.1") / UDP(dport=20001, sport=ord(l))
        send(packet)

if __name__ == "__main__":
    if "S" in sys.argv:
        server()
    else:
        client()
