#!/usr/bin/env python

from os import path as os_path
from random import choice, uniform
from sys import path as sys_path
from uuid import uuid4
from time import sleep

from ghost_protocol import INTER_REQUEST_ADDRESS, INTER_PUBSUB_ADDRESS
from ghost_protocol.communicator import Communicator
from ghost_protocol.inter_pb2 import (
    Devices, DevicesInfo, InterfaceConfigSet, InterfaceId,
    InterfacesInfo, IptablesResult, IptablesAppend, IptablesDelete)

# add parent directory to Python path for ghost & tests packages to be found
sys_path.append(os_path.realpath(os_path.dirname(__file__) + "/.."))

# pylint: disable=E1101
# InterfaceConfigSet used for interfaces.config request
INTERFACECONFIGSET = InterfaceConfigSet()
INTERFACECONFIGSET.id.value = str(uuid4())
INTERFACECONFIGSET.config.pcap_path = "pcap_path"
INTERFACECONFIGSET.config.pcap_prefix = "pcap_prefix"
INTERFACECONFIGSET.config.pcap_duration = 30
INTERFACECONFIGSET.config.pcap_size = 4
INTERFACECONFIGSET.config.pcap_count = 5
INTERFACECONFIGSET.config.tshark.filter = "filter"
INTERFACECONFIGSET.config.tshark.snaplen = 6
INTERFACECONFIGSET.config.tshark.promiscuous = False
INTERFACECONFIGSET.config.tshark.promiscuous = 4
INTERFACECONFIGSET.config.tshark.link_type = "link_type"

# InterfaceId used for interfaces.start and interfaces.stop requests
INTERFACEID = InterfaceId()
INTERFACEID.value = str(uuid4)

# Devices used for blacklist.add and blacklist.remove requests
DEVICES = Devices()
device_id = DEVICES.devices.add()
device_id.value = str(uuid4())

device_id = DEVICES.devices.add()
device_id.value = str(uuid4())

# IptablesAppend used for iptables.append request
IPTABLESAPPEND = IptablesAppend()
IPTABLESAPPEND.chain = "chain"
IPTABLESAPPEND.rule = "rule"

# IptablesDelete used for iptables.delete request
IPTABLESDELETE = IptablesDelete()
IPTABLESDELETE.chain = "chain"
IPTABLESDELETE.rule = "rule"
IPTABLESDELETE.num = 3

# pylint: enable=E1101


class Module:
    """Mockup of a GHOST module receiving notifications from a gateway."""

    def __init__(self):
        self._communicator = Communicator(
            None,
            None,
            None,
            [("gateway", INTER_REQUEST_ADDRESS)],
            [Communicator.Subscription(
                INTER_PUBSUB_ADDRESS,
                ["device"], self._on_notification)])

        self.request = self._communicator.request
        self.publish = self._communicator.publish
        self.stop = self._communicator.stop

    @staticmethod
    def _on_notification(name, data):
        print("Notification: [{}, {}]".format(
            name, "".join(["/x%02x" % ord(c) for c in str(data)])))


def on_interfaces(data):
    if data is None:
        print("on_interfaces timeout!")
    else:
        devices = InterfacesInfo()
        devices.ParseFromString(data)
        print(devices)


def on_interfaces_config(data):
    if data is None:
        print("on_interfaces_config timeout!")
    else:
        print("Interface configured.")


def on_interfaces_start(data):
    if data is None:
        print("on_interfaces_start timeout!")
    else:
        print("Interface started.")


def on_interfaces_stop(data):
    if data is None:
        print("on_interfaces_stop timeout!")
    else:
        print("Interface stopped.")


def on_devices(data):
    if data is None:
        print("on_devices timeout!")
    else:
        devices = DevicesInfo()
        devices.ParseFromString(data)
        print("Devices:", devices)


def on_blacklist(data):
    if data is None:
        print("on_blacklist timeout!")
    else:
        devices = Devices()
        devices.ParseFromString(data)
        print("Blacklist devices:", devices)


def on_blacklist_add(data):
    if data is None:
        print("on_blacklist_add timeout!")
    else:
        print("Device added to blacklist.")


def on_blacklist_remove(data):
    if data is None:
        print("on_blacklist_remove timeout!")
    else:
        print("Device removed from blacklist.")


def on_iptables_append(data):
    if data is None:
        print("on_iptables_append timeout!")
    else:
        result = IptablesResult()
        result.ParseFromString(data)
        # pylint: disable=E1101
        if result.code == IptablesResult.SUCCESS:
            print("Rule appended")
        else:
            print("Rule not appended")
        # pylint: enable=E1101


def on_iptables_delete(data):
    if data is None:
        print("on_iptables_delete timeout!")
    else:
        result = IptablesResult()
        result.ParseFromString(data)
        # pylint: disable=E1101
        if result.code == IptablesResult.SUCCESS:
            print("Rule deleted")
        else:
            print("Rule not deleted")
        # pylint: enable=E1101


def _main():

    module = Module()

    # periodically send get_devices request
    while True:
        try:
            sleep(uniform(1.0, 5.0))
        except KeyboardInterrupt:
            print("Terminating...")
            break
        request = choice([("interfaces.get", None, on_interfaces),
                          ("interfaces.config",
                           INTERFACECONFIGSET.SerializeToString(),
                           on_interfaces_config),
                          ("interfaces.start",
                           INTERFACEID.SerializeToString(),
                           on_interfaces_start),
                          ("interfaces.stop",
                           INTERFACEID.SerializeToString(),
                           on_interfaces_stop),
                          ("devices.get", None, on_devices),
                          ("blacklist.get", None, on_blacklist),
                          ("blacklist.add",
                           DEVICES.SerializeToString(),
                           on_blacklist_add),
                          ("blacklist.remove",
                           DEVICES.SerializeToString(),
                           on_blacklist_remove),
                          ("iptables.append",
                           IPTABLESAPPEND.SerializeToString(),
                           on_iptables_append),
                          ("iptables.delete",
                           IPTABLESDELETE.SerializeToString(),
                           on_iptables_delete)])
        print("{}...".format(request[0]))
        module.request("gateway", request[0], request[1], request[2])

    module.stop()
    print("Terminated.")

if __name__ == "__main__":
    _main()
