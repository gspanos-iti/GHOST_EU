import sys
import pyshark
import json

def process_packet(p):
    
    packet_details = {}
    packet_details["time"] = float(p.sniff_timestamp)  # time
    data_layer = p.data.data 
    packet_details["length"] = int(data_layer[:2]) # payload length in bytes
    packet_details["type"] = data_layer[2:4]
    packet_details["address"] =  data_layer[4:10]
    if (packet_details["length"] >4): # length of payload is greater than 4, means contains data in the payload
        packet_details["data"] =data_layer [10:-4] 
    else:
        packet_details["data"] = ""  # no data in the payload
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
