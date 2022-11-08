#!/usr/bin/env python3
hosts = []

from scapy.all import *
import os
from art import *


def printToHTML(packet):
   HTMLWrite = open("log.html","a")
   HTMLWrite.write(packet + "\n")
   HTMLWrite.close()


def clear():
     os.system('cls' if os.name=='nt' else 'clear')
     return("   ")

def handler(packet):
    myPacket = packet.summary()
    sender, receiver = filterList(myPacket)
    checkIfExists(sender)
    checkIfExists(receiver)



def filterList(packet):
    mypacketlist = packet.split(" ")
    if len(mypacketlist[5].split(':')) > 1 and len(mypacketlist[7].split(':')) > 1:
        sender = mypacketlist[5].split(':')[0]
        receiver = mypacketlist[7].split(':')[0]
        print(sender)
        return sender,receiver
    else:
        return "false", "false"


def checkIfExists(inHost):
    status = False
    for host in hosts:
        if inHost == host:
            status = True;
    
    if status == False and inHost != "false":
        hosts.append(inHost)
        printToHTML(inHost)


    clear()
    tprint("Hosts")
    print(hosts)
            




if __name__ == "__main__":
    sniff(iface="en0", prn=handler, store=0)