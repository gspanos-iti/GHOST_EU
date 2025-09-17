# +two files for zb_process 
# +extract fields of ZB
 
import sys
import pyshark
import json


def process_packet(p):
    
    packet_details = {}
    packet_details["time"] = float(p.sniff_timestamp)  # time
    packet_details["length"] = int(p.length) # packet length in bytes
    packet_details["src_zb_addr"] =  p.wpan.src16 # source address 
    packet_details["dst_zb_addr"] =  p.wpan.dst16 # destination address 
    packet_details["dst_zb_pan"] =  p.wpan.dst_pan # destination PAN - personal area network 
    packet_details["data_length"] = int(p.data.len) # data length in bytes
    packet_details["data"] = p.data.data
    return(packet_details)

path = sys.argv[1]
cap = pyshark.FileCapture(path)  # Read pcap through pyshark library
packets = []
for p in cap:
    packets.append(process_packet(p))
print(json.dumps(packets))

if not cap.eventloop.is_closed():
    cap.eventloop.close()
del cap
