from scapy.all import *

pkt = Ether(src="cc:cc:cc:cc:cc:cc", type=0x0800)/IP(dst="10.11.12.13", proto=6)/TCP(dport=776)

sendp(pkt, 'veth4')
