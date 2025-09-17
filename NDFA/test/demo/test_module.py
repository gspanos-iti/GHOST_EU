from time import sleep
from random import uniform
import uuid

from ghost_protocol.inter_pb2 import InterfaceId
from ghost_protocol.ndfa_pb2 import FileProcessing
from ghost_protocol.communicator import Communicator
from ghost_ndfa import NDFA_PUBSUB_ADDRESS, NDFA_ALERT_TOPIC


class Module:
    """Mockup of a NDFA module publishing notifications."""

    def __init__(self):
        self._communicator = Communicator(
            None,
            None,
            NDFA_PUBSUB_ADDRESS,
            [],
            [])

        self.publish = self._communicator.publish
        self.stop = self._communicator.stop


def generate_packet():

    # pylint: disable=E1101
    alert_type = FileProcessing.BEGIN
    if_id = InterfaceId()
    if_id.value = str(uuid.uuid4())
    file_name = "/home/szanto/Repositories/ghost-master/NDFA/pcap_files/input.pcap"

    alert = FileProcessing()
    alert.alert_type = alert_type
    alert.if_id.value = if_id.value
    alert.file_name = file_name
    # pylint: enable=E1101

    return (NDFA_ALERT_TOPIC, alert.SerializeToString())


def _main():

    module = Module()

    # periodically publish event
    while True:
        try:
            sleep(uniform(1.0, 5.0))
            topic, data = generate_packet()
            module.publish(topic, data)
        except KeyboardInterrupt:
            print("Terminating...")
            break

    module.stop()
    print("Terminated.")

if __name__ == "__main__":
    _main()
