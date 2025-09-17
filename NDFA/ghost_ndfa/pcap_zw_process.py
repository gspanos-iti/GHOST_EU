import sys
import pyshark
import json


def process_packet(p):
    if 'ETH' in str(p.layers):
        packet_details = {}
        packet_details["time"] = float(p.sniff_timestamp)  # time
        packet_details["src_zw_addr"] = p.eth.src  # Source zw address
        packet_details["dst_zw_addr"] = p.eth.dst  # Destination zw address
        packet_details["length"] = int(p.data.len)  # length in bytes
        packet_details["data"] = p.data.data  # length in bytes

        payload_str = packet_details["data"].decode("hex")
        if "=" in payload_str:
            payload_list = payload_str.split(" ")
            parameters = {}
            for i in payload_list:
                data = i.split("=")
                if len(data) == 2:
                    parameters[data[0]] = data[1]
            packet_details["text"] = parameters
        else:
            packet_details["text"] = payload_str

        return packet_details

    else:
        return None

path = sys.argv[1]
cap = pyshark.FileCapture(path)  # Read pcap through pyshark library
packets = []
for p in cap:
    fp = process_packet(p)
    if fp is not None: # Maybe we should add a packet with too few fields and do not add it to batches
        packets.append(fp)
print(json.dumps(packets))

if not cap.eventloop.is_closed():
    cap.eventloop.close()
del cap
