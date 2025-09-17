from scapy.all import hexdump,rdpcap
import sys

f = sys.argv[1]
for i,p in enumerate(rdpcap(f)):
	hexdump(p.payload)
	print("*************************")
