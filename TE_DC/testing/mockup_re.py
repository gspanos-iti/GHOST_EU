from time import sleep
import sys,os
import signal
sys.path.append(os.path.relpath(os.path.join('../communication_protocols/python')))
from ghost_protocol.communicator import Communicator
from ghost_protocol.te_dc_pb2 import AnomalyDetection
sys.path.append(os.path.relpath(os.path.join('../TE_DC')))
# the address that the TE_DC publish abnormal behavior alert via ICC
from ghost_te_dc import TE_DC_PUBSUB_ADDRESS, TE_DC_ALERT_TOPIC

class Module:
    """Mockup of a RE module receiving notifications from TE_DC module."""

    def __init__(self):
        self._communicator = Communicator(
            None,
            None,
            None,
            [],
            [Communicator.Subscription(TE_DC_PUBSUB_ADDRESS,
                                       [TE_DC_ALERT_TOPIC], self._on_notification)])

        self.runner = True
        print("Running...")


    @staticmethod
    def _on_notification(name, data):
        alert = AnomalyDetection()
        alert.ParseFromString(data)
        print(alert)
        print("-------------------------------------")

    def stop(self):
        self._communicator.stop()
        self.runner = False

def signal_handler(signum, frame):
    """Signal handler which stops the RE module upon reception of a signal."""
    print('Signal received: stopping...')
    module.stop()

if __name__ == "__main__":
    module = Module()

    if sys.platform.startswith('linux'):
        signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    while module.runner:
        try:
            time.sleep(1)
        except Exception:
            pass