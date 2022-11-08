import argparse
from scapy.all import *

def print_ports(port, state):
	print("%s | %s" % (port, state))

scantype = "syn"

def printToHTML(packet):
   HTMLWrite = open("log.html","a")
   HTMLWrite.write(packet + "\n")
   HTMLWrite.close()


# syn scan
def syn_scan(target, ports):
	print("syn scan on, %s with ports %s" % (target, ports))
	sport = RandShort()
	for port in ports:
		pkt = sr1(IP(dst=target)/TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)
		if pkt != None:
			if pkt.haslayer(TCP):
				if pkt[TCP].flags == 20:
					print_ports(port, "")
				elif pkt[TCP].flags == 18:
					print_ports(port, "Open")
					printToHTML(ports + "open\n")
				else:
					print_ports(port, "TCP packet resp / filtered")
			elif pkt.haslayer(ICMP):
				print_ports(port, "ICMP resp / filtered")
			else:
				print_ports(port, "Unknown resp")
				print(pkt.summary())
		else:
			print_ports(port, "Unanswered")

