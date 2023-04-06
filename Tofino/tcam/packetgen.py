from scapy.all import *

pkt = Ether(src="ab:cd:ab:cd:ab:cd",dst="ba:dc:ba:dc:ba:dc",type=0x0800)/IP(src="10.11.12.13", dst="13.12.11.10", proto=6)/TCP(sport=6767,dport=7676)

sendp(pkt, 'veth4')
