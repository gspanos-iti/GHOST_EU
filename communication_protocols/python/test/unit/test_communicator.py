import logging
import unittest
import time
from uuid import uuid4

from ghost_protocol.communicator import Communicator

from ghost_protocol.inter_pb2 import(
    Devices, DevicesInfo, InterfaceConfigSet,
    InterfacesInfo, InterfaceId, IptablesResult, IptablesAppend,
    IptablesDelete, IptablesInfo, IP4, ZWAVE)

INTER_REQUEST_ADDRESS = "tcp://127.0.0.1:10001"
INTER_PUBSUB_ADDRESS = "tcp://127.0.0.1:10002"

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


class MockupModule:
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

    @staticmethod
    def on_interfaces(data):
        if data is None:
            print("on_interfaces timeout!")
        else:
            devices = InterfacesInfo()
            devices.ParseFromString(data)
            print(devices)

    @staticmethod
    def on_interfaces_config(data):
        if data is None:
            print("on_interfaces_config timeout!")
        else:
            print("Interface configured.")

    @staticmethod
    def on_interfaces_start(data):
        if data is None:
            print("on_interfaces_start timeout!")
        else:
            print("Interface started.")

    @staticmethod
    def on_interfaces_stop(data):
        if data is None:
            print("on_interfaces_stop timeout!")
        else:
            print("Interface stopped.")

    @staticmethod
    def on_devices(data):
        if data is None:
            print("on_devices timeout!")
        else:
            devices = DevicesInfo()
            devices.ParseFromString(data)
            print("Devices:", devices)

    @staticmethod
    def on_blacklist(data):
        if data is None:
            print("on_blacklist timeout!")
        else:
            devices = Devices()
            devices.ParseFromString(data)
            print("Blacklist devices:", devices)

    @staticmethod
    def on_blacklist_add(data):
        if data is None:
            print("on_blacklist_add timeout!")
        else:
            print("Device added to blacklist.")

    @staticmethod
    def on_blacklist_remove(data):
        if data is None:
            print("on_blacklist_remove timeout!")
        else:
            print("Device removed from blacklist.")

    @staticmethod
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

    @staticmethod
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

    @staticmethod
    def on_iptables(data):
        if data is None:
            print("on_iptables timeout!")
        else:
            result = IptablesInfo()
            result.ParseFromString(data)
            # pylint: disable=E1101
            print("Iptables:", result)
            # pylint: enable=E1101


class MockupGateway:
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
        self.counter = 0

    def _on_request(self, request):
        if request.name == "interfaces.get":
            logging.info("interfaces.get request received")
            request.reply(INTERFACESINFO.SerializeToString())
            logging.info("interfaces.get reply sent")
        elif request.name == "interfaces.config":
            logging.info("interfaces.config request received")
            interfaceConfigSet = InterfaceConfigSet()
            interfaceConfigSet.ParseFromString(request.data)
            request.reply("")
            logging.info("interfaces.config reply sent")
        elif request.name == "interfaces.start":
            logging.info("interfaces.start request received")
            interfaceId = InterfaceId()
            interfaceId.ParseFromString(request.data)
            request.reply("")
            logging.info("interfaces.start reply sent")
        elif request.name == "interfaces.stop":
            logging.info("interfaces.stop request received")
            interfaceId = InterfaceId()
            interfaceId.ParseFromString(request.data)
            request.reply("")
            logging.info("interfaces.stop reply sent")
        elif request.name == "devices.get":
            logging.info("devices.get request received")
            request.reply(DEVICESINFO.SerializeToString())
            logging.info("devices.get reply sent")
        elif request.name == "blacklist.get":
            logging.info("blacklist.get request received")
            request.reply(DEVICES.SerializeToString())
            logging.info("blacklist.get reply sent")
        elif request.name == "blacklist.add":
            logging.info("blacklist.add request received")
            devices = Devices()
            devices.ParseFromString(request.data)
            request.reply("")
            logging.info("blacklist.add reply sent")
        elif request.name == "blacklist.remove":
            logging.info("blacklist.remove request received")
            devices = Devices()
            devices.ParseFromString(request.data)
            request.reply("")
            logging.info("blacklist.remove reply sent")
        elif request.name == "iptables.append":
            logging.info("iptables.append request received")
            result = IptablesResult()
            # pylint: disable=E1101
            result.code = IptablesResult.SUCCESS
            # pylint: enable=E1101
            request.reply(result.SerializeToString())
            logging.info("iptables.append reply sent")
        elif request.name == "iptables.delete":
            logging.info("iptables.delete request received")
            result = IptablesResult()
            # pylint: disable=E1101
            result.code = IptablesResult.SUCCESS
            # pylint: enable=E1101
            request.reply(result.SerializeToString())
            logging.info("iptables.delete reply sent")
        elif request.name == "iptables.get":
            logging.info("iptables.get request received")
            result = IptablesInfo()
            # pylint: disable=E1101
            rules = ["list", "of", "strings"]
            for rule in rules:
                # pylint: disable=E1101
                entry = result.entries.add()
                # pylint: enable=E1101
                entry.rule = rule
            # pylint: enable=E1101
            request.reply(result.SerializeToString())
            logging.info("iptables.get reply sent")
        self.counter = self.counter + 1


class TestCommunicator(unittest.TestCase):

    """
    Test suite for communicator.
    """

    def setUp(self):
        # Setup for the test case.
        pass

    def tearDown(self):
        # Here you can make the cleanup for the next test.
        pass

    def test_communicator_requests(self):
        """
        Test for the requests.
        """
        module = MockupModule()
        Communicator._CONTROL_ADDRESS = "inproc://control2"
        gateway = MockupGateway()
        requests = [("interfaces.get", None, module.on_interfaces),
                    ("interfaces.config",
                     INTERFACECONFIGSET.SerializeToString(),
                     module.on_interfaces_config),
                    ("interfaces.start",
                     INTERFACEID.SerializeToString(),
                     module.on_interfaces_start),
                    ("interfaces.stop",
                     INTERFACEID.SerializeToString(),
                     module.on_interfaces_stop),
                    ("devices.get", None, module.on_devices),
                    ("blacklist.get", None, module.on_blacklist),
                    ("blacklist.add",
                     DEVICES.SerializeToString(),
                     module.on_blacklist_add),
                    ("blacklist.remove",
                     DEVICES.SerializeToString(),
                     module.on_blacklist_remove),
                    ("iptables.append",
                     IPTABLESAPPEND.SerializeToString(),
                     module.on_iptables_append),
                    ("iptables.delete",
                     IPTABLESDELETE.SerializeToString(),
                     module.on_iptables_delete),
                    ("iptables.get", None, module.on_iptables)]
        for request in requests:
            module.request("gateway", request[0], request[1], request[2])

        while gateway.counter != len(requests):
            time.sleep(0.2)

        module.stop()
        gateway.stop()
