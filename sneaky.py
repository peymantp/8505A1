#!/usr/bin/python3

import sys
import os
import argparse
import time
from scapy.all import *

'''
Program argument initialization 
./sneaky.py -s 192.168.0.4 -sport 80 -d 192.168.0.7 -dport 80 -f ./sneaky.py -t TCP -mode server
sudo python3 sneaky.py -f ./server.py -t TCP -mode server
'''
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
arg_parser.add_argument('-t','-transport',dest='transport', help='TCP or UDP')
arg_parser.add_argument('-mode',dest='mode', help='server or client')
args = arg_parser.parse_args()

que_out=None
que_in=[]
packet_num=0

def client_input():
    if args.file is not None:
        print('reading file')
        with open(args.file, 'r') as f:
            que_out = f.read()
        print(que_out)
    elif args.msg is not None:
        que_out = args.msg
    else:
        print('Select either file or massage to send')
        exit()

def craft(character):
    global packet_num
    dport=int(args.des_port)
    sport=int(args.src_port)
    #char = character.encode('utf-8')
    char = ord(character)
    if args.transport == 'TCP':
        pck=IP(dst=args.des_ip, src=args.src_ip,ttl=char)/TCP(sport=packet_num,dport=dport,flags="SE")
    elif args.transport == 'UDP':
        pck=IP(dst=args.des_ip, src=args.src_ip,ttl=char)/UDP(sport=packet_num,dport=dport)
    packet_num=1+packet_num
    return pck
    
def client():
    for char in que_out:
        pkt = craft(char)
        print(pkt)
        send(pkt)
        #time.sleep(RandNum(1,4))

def parse_tcp(pkt: Packet):
    flags=pkt['TCP'].flags
    if flags == 0x042:
        que_in.append(chr(pkt['IP'].ttl))
        print(''.join(que_in))
        
def parse_udp(pck):
    return pck

def server():
    if args.transport == 'TCP':
        print('Detecting TCP packets')
        sniff(filter="tcp", prn=parse_tcp)
    elif args.transport == 'UDP':
        print('Detecting UDP packets')
        sniff(filter="udp", prn=parse_udp)

if args.mode == 'server':
    server()
elif args.mode == 'client':
    input()
    client_input()