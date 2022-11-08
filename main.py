#!/usr/bin/env python3
import service_scanner as SS
import live_scanner as LS
import host_sum as HS
import port_scanner as PS
from scapy.all import *


selection = input("1. service scanner\n2. live scanner\n3. host sum\n 4.port scanner\n:")

if selection == "1": 
    sniff(iface="en0", prn=SS.handler, store=0)

if selection == "2": 
    sniff(iface="en0", prn=LS.handler, store=0)

if selection == "3": 
    sniff(iface="en0", prn=HS.handler, store=0)

if selection == "4":
    target = input("targetIP: ")
    PS.syn_scan(target, [item for item in range(1, 10000)])














