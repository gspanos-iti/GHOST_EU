import sys
import pyshark
import json


def process_packet(p):
    packet_details = {}

    packet_details["bt_type"] = p.hci_h4.type  # HCI Command Packet, HCI Event Packet, HCI ACL Data Packet and HCI Synchronous Data Packet
    packet_details["direction"] = p.hci_h4.direction
    packet_details["time"] = float(p.sniff_timestamp)  # time
    packet_details["length"] = int(p.length)  # lenght in bytes


    if packet_details["bt_type"] == "0x00000001" or packet_details["bt_type"] == "1":  # bthci_cmd packet
        packet_details["opcode"] = int(p.bthci_cmd.opcode)  # Command Opcode
        packet_details["opcode_ocf"] = int(p.bthci_cmd.opcode_ocf)  # Opcode Command Field
        packet_details["opcode_ogf"] = int(p.bthci_cmd.opcode_ogf)  # Opcode Group Field
        packet_details["param_length"] = int(p.bthci_cmd.param_length)  # Parameter Total Length
        packet_details["taxonomy"] = "man"  # Packet taxonomy
    elif packet_details["bt_type"] == "0x00000002" or packet_details["bt_type"] == "2":  # ACL data packet
        packet_details["data_length"] = int(p.bthci_acl.length)  # Data length
        packet_details["src_bd_addr"] = p.bthci_acl.src_bd_addr  # Source bt address
        packet_details["dst_bd_addr"] = p.bthci_acl.dst_bd_addr  # Destination bt address
        packet_details["taxonomy"] = "data"  # Packet taxonomy
        if hasattr (p, 'btatt') and hasattr (p.btatt, 'opcode') and hasattr (p.btatt, 'service_uuid16') and hasattr (p.btatt, 'value'):
                packet_details["btatt.opcode"] = p.btatt.opcode  #  Method Attribute Opcode-->Handle Value Indication
                packet_details["btatt.service_uuid16"] = p.btatt.service_uuid16 #  Service UUID -->Weight Scale
                packet_details["btatt.value"] = p.btatt.value  # value of Attribute
    elif packet_details["bt_type"] == "0x00000004" or packet_details["bt_type"] == "4":  # event packet
        packet_details["event_code"] = int(p.bthci_evt.code)
        packet_details["taxonomy"] = "man"  # Packet taxonomy


    return packet_details

path = sys.argv[1]
bt_ignore_man_packets = sys.argv[2] #boolean of ignore managment packets pass as third parameter

cap = pyshark.FileCapture(path)  # Read pcap through pyshark library
packets = []
for p in cap:
    if p.hci_h4.type == "0x00000002" or p.hci_h4.type  == "2" or bt_ignore_man_packets==str(False) :   
		packets.append(process_packet(p))
print(json.dumps(packets))

if not cap.eventloop.is_closed():
    cap.eventloop.close()
del cap


