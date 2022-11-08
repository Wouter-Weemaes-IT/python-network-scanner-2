#!/usr/bin/env python3
protocols = []

from scapy.all import *
import os
from art import *

def clear():
     os.system('cls' if os.name=='nt' else 'clear')
     return("   ")

def handler(packet):
    myPacket = packet.summary()
    sender, receiver = filterList(myPacket)
    if(any(c.isalpha() for c in sender)):
        checkIfExists(sender)
    if(any(c.isalpha() for c in receiver)):
        checkIfExists(receiver)



def filterList(packet):
    mypacketlist = packet.split(" ")
    if len(mypacketlist[5].split(':')) > 1 and len(mypacketlist[7].split(':')) > 1:
        sender = mypacketlist[5].split(':')[1]
        receiver = mypacketlist[7].split(':')[1]
        return sender,receiver
    else:
        return "false", "false"


def checkIfExists(inProt):
    status = False
    for prot in protocols:
        if inProt == prot:
            status = True;
    
    if status == False and inProt != "false":
        protocols.append(inProt)
    clear()
    tprint("Network Protocols")
    print(protocols)
            




if __name__ == "__main__":
    sniff(iface="en0", prn=handler, store=0)