#!/usr/bin/env python3
from art import *
from scapy.all import *
import os

def clear():
     os.system('cls' if os.name=='nt' else 'clear')
     return("   ")


def handler(packet):
    print(packet.summary())


if __name__ == "__main__":
    clear()
    tprint("Live scanner")
    sniff(iface="en0", prn=handler, store=0)

