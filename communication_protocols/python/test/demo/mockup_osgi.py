#!/usr/bin/env python

from random import choice, uniform, randint
from os import urandom
from os import path as os_path
from sys import path as sys_path

from time import sleep
from uuid import uuid4

from ghost_protocol import Communicator
from ghost_protocol.televes_proxy import (
    OSGI_REQUEST_ADDRESS, OSGI_PUBSUB_ADDRESS)
from ghost_protocol.inter_pb2 import DeviceInfo, DevicesInfo, ZWAVE

# add parent directory to Python path for ghost & tests packages to be found
sys_path.append(os_path.realpath(os_path.dirname(__file__) + "/.."))

# Device List
# mockup of devices attached to the gateway
DEVICES = DevicesInfo()

# pylint: disable=E1101
device_info = DEVICES.devices.add()
device_info.id.value = str(uuid4())
device_info.description = "Smoke Sensor"
device_info.type = ZWAVE
device_info.zwave.home_id = "00-14-22-01-23-45"
device_info.zwave.node_id = 4

device_info = DEVICES.devices.add()
device_info.id.value = str(uuid4())
device_info.description = "Light Switch"
device_info.type = ZWAVE
device_info.zwave.home_id = "00-14-22-01-23-45"
device_info.zwave.node_id = 6
# pylint: enable=E1101


class Osgi:

    def __init__(self):
        self._communicator = Communicator(
            OSGI_REQUEST_ADDRESS,
            self._on_request,
            OSGI_PUBSUB_ADDRESS,
            [],
            [])

        self.publish = self._communicator.publish
        self.stop = self._communicator.stop

    @staticmethod
    def _on_request(request):
        if request.name == "devices.get":
            print("devices.get request received")
            request.reply(DEVICES.SerializeToString())
            print("devices.get reply sent")


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
    osgi = Osgi()

    while True:
        try:
            sleep(uniform(0.2, 3.0))
        except KeyboardInterrupt:
            print("Terminating...")
            break
        topic, data = generate_packet()
        print("Publish: [{}, {}]".format(
            topic, "".join(["/x%02x" % ord(c) for c in str(data)])))
        osgi.publish(topic, data)

    osgi.stop()
    print("Terminated.")

if __name__ == "__main__":
    _main()
