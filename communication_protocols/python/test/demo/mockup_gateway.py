#!/usr/bin/env python

from os import urandom, path as os_path
from random import choice, randint, uniform
from sys import path as sys_path
from uuid import uuid4
from time import sleep

from ghost_protocol.communicator import Communicator
from ghost_protocol.inter_pb2 import(
    Devices, DeviceInfo, DevicesInfo, InterfaceConfigSet,
    InterfacesInfo, InterfaceId, IptablesResult, IP4, ZWAVE)
from ghost_protocol import INTER_REQUEST_ADDRESS, INTER_PUBSUB_ADDRESS

# add parent directory to Python path for ghost & tests packages to be found
sys_path.append(os_path.realpath(os_path.dirname(__file__) + "/.."))

# pylint: disable=E1101
INTERFACESINFO = InterfacesInfo()

# Interface List
# mockup of interfaces attached to the gateway
interface_info = INTERFACESINFO.interfaces.add()
interface_info.type = IP4
interface_info.id.value = str(uuid4())
interface_info.description = "ETH0 Interface"
interface_info.started = False
interface_info.tshark = False
interface_info.address = "127.0.0.1"

interface_info = INTERFACESINFO.interfaces.add()
interface_info.type = ZWAVE
interface_info.id.value = str(uuid4())
interface_info.description = "Z-Wave Interface"
interface_info.started = True
interface_info.tshark = False

# Device List
# mockup of devices attached to the gateway
DEVICESINFO = DevicesInfo()

device_info = DEVICESINFO.devices.add()
device_info.id.value = str(uuid4())
device_info.description = "Smoke Sensor"
device_info.type = ZWAVE
device_info.zwave.home_id = "00-14-22-01-23-45"
device_info.zwave.node_id = 4

device_info = DEVICESINFO.devices.add()
device_info.id.value = str(uuid4())
device_info.description = "Light Switch"
device_info.type = ZWAVE
device_info.zwave.home_id = "00-14-22-01-23-45"
device_info.zwave.node_id = 6

# Devices used for blacklist.get
DEVICES = Devices()
device_id = DEVICES.devices.add()
device_id.value = str(uuid4())

device_id = DEVICES.devices.add()
device_id.value = str(uuid4())
# pylint: enable=E1101


class Gateway:
    """Mockup of a gateway implementing Interoperability Layer"""

    def __init__(self):
        self._communicator = Communicator(
            INTER_REQUEST_ADDRESS,
            self._on_request,
            INTER_PUBSUB_ADDRESS,
            [],
            [])

        self.publish = self._communicator.publish
        self.stop = self._communicator.stop

    @staticmethod
    def _on_request(request):
        if request.name == "interfaces.get":
            print("interfaces.get request received")
            request.reply(INTERFACESINFO.SerializeToString())
            print("interfaces.get reply sent")
        elif request.name == "interfaces.config":
            print("interfaces.config request received")
            interfaceConfigSet = InterfaceConfigSet()
            interfaceConfigSet.ParseFromString(request.data)
            request.reply("")
            print("interfaces.config reply sent")
        elif request.name == "interfaces.start":
            print("interfaces.start request received")
            interfaceId = InterfaceId()
            interfaceId.ParseFromString(request.data)
            request.reply("")
            print("interfaces.start reply sent")
        elif request.name == "interfaces.stop":
            print("interfaces.stop request received")
            interfaceId = InterfaceId()
            interfaceId.ParseFromString(request.data)
            request.reply("")
            print("interfaces.stop reply sent")
        elif request.name == "devices.get":
            print("devices.get request received")
            request.reply(DEVICESINFO.SerializeToString())
            print("devices.get reply sent")
        elif request.name == "blacklist.get":
            print("blacklist.get request received")
            request.reply(DEVICES.SerializeToString())
            print("blacklist.get reply sent")
        elif request.name == "blacklist.add":
            print("blacklist.add request received")
            devices = Devices()
            devices.ParseFromString(request.data)
            request.reply("")
            print("blacklist.add reply sent")
        elif request.name == "blacklist.remove":
            print("blacklist.remove request received")
            devices = Devices()
            devices.ParseFromString(request.data)
            request.reply("")
            print("blacklist.remove reply sent")
        elif request.name == "iptables.append":
            print("iptables.append request received")
            result = IptablesResult()
            # pylint: disable=E1101
            result.code = IptablesResult.SUCCESS
            # pylint: enable=E1101
            request.reply(result.SerializeToString())
            print("iptables.append reply sent")
        elif request.name == "iptables.delete":
            print("iptables.delete request received")
            result = IptablesResult()
            # pylint: disable=E1101
            result.code = IptablesResult.SUCCESS
            # pylint: enable=E1101
            request.reply(result.SerializeToString())
            print("iptables.delete reply sent")


def generate_packet():
    types = ["pcap.bluetooth", "pcap.ip", "pcap.zigbee", "pcap.zwave",
             "devices.added", "devices.removed"]
    size = randint(10, 30)

    event = choice(types)
    if event in ["devices.added", "devices.removed"]:
        # pylint: disable=E1101
        device = DeviceInfo()
        device.id.value = str(uuid4())
        device.description = "Smoke Sensor"
        device.type = ZWAVE
        device.zwave.home_id = "00-14-22-01-23-45"
        device.zwave.node_id = 4
        # pylint: enable=E1101
        return (event, device.SerializeToString())

    return (event, urandom(size))


def _main():
    gateway = Gateway()

    while True:
        try:
            sleep(uniform(0.2, 3.0))
        except KeyboardInterrupt:
            print("Terminating...")
            break
        topic, data = generate_packet()

        print("Publish: [{}, {}]".format(
            topic, "".join(["/x%02x" % ord(c) for c in str(data)])))
        gateway.publish(topic, data)

    gateway.stop()
    print("Terminated.")

if __name__ == "__main__":
    _main()
