#!/usr/bin/env python

import argparse
import signal
import sys
import os
from time import sleep
import daemon

from lockfile.pidlockfile import PIDLockFile
from ghost_protocol import INTER_REQUEST_ADDRESS, INTER_PUBSUB_ADDRESS
from ghost_protocol.communicator import Communicator

HAL_REQUEST_ADDRESS = "ipc:///tmp/ghost/hal.query"
OSGI_REQUEST_ADDRESS = "ipc:///tmp/ghost/osgi.query"
OSGI_PUBSUB_ADDRESS = "ipc:///tmp/ghost/osgi.notify"


class TelevesProxy:
    """
    The proxy receives requests and forwards them to the appropriate gateway.
    If the operation is 'devices.get' then the request will be forwarded to
    the OSGI gateway, else it will be forwarded to the HAL gateway.
    Notifications received from the OSGI gateway will be published on
    INTER_PUBSUB_ADDRESS.
    """
    def __init__(self):
        self._hal_requests = {'interfaces.get', 'interfaces.config',
                              'interfaces.start', 'interfaces.stop',
                              'blacklist.get', 'blacklist.add',
                              'blacklist.remove', 'iptables.append',
                              'iptables.delete'}
        self._osgi_requests = {'devices.get'}

        self._communicator = Communicator(
            INTER_REQUEST_ADDRESS,
            self._on_request,
            INTER_PUBSUB_ADDRESS,
            [("hal", HAL_REQUEST_ADDRESS), ("osgi", OSGI_REQUEST_ADDRESS)],
            [Communicator.Subscription(
                OSGI_PUBSUB_ADDRESS,
                ["device"], self._on_notification)])

        self.publish = self._communicator.publish
        self._is_running = True

    def _on_request(self, request):
        handler = lambda x: self._on_response(request, x)
        if request.name in self._osgi_requests:
            self._communicator.request("osgi", request.name, request.data,
                                       handler)
        elif request.name in self._hal_requests:
            self._communicator.request("hal", request.name, request.data,
                                       handler)

    @staticmethod
    def _on_response(request, data):
        request.reply(data)

    def _on_notification(self, topic, data):
        self._communicator.publish(topic, data)

    def stop(self):
        self._communicator.stop()
        self._is_running = False

    @property
    def is_running(self):
        return self._is_running

# pylint: disable=W0613
def signal_handler(signum, frame):
    proxy.stop()
# pylint: enable=W0613

def run():
    # pylint: disable=W0601
    global proxy
    # pylint: enable=W0601
    proxy = TelevesProxy()
    while proxy.is_running:
        sleep(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The Televes proxy.")

    if sys.platform.startswith('linux'):
        parser.add_argument(
            "--no-fork", "-n", help="do not fork into the background",
            action="store_const", const=True)
        parser.add_argument(
            "--pidfile", "-p",
            help="path to the PID file when running as daemon (in background)",
            type=str)

    args = parser.parse_args()

    if sys.platform.startswith('linux') and not args.no_fork:
        daemon_context = daemon.DaemonContext()
        daemon_context.signal_map = {
            signal.SIGTERM: signal_handler,
            signal.SIGINT: signal_handler,
            signal.SIGQUIT: signal_handler,
            signal.SIGUSR1: signal_handler,
            signal.SIGHUP: signal_handler}

        daemon_context.working_directory = os.getcwd()
        if args.pidfile:
            daemon_context.pidfile = PIDLockFile(args.pidfile, timeout=5)

        with daemon_context:
            run()

    else:

        if sys.platform.startswith('linux'):
            signal.signal(signal.SIGQUIT, signal_handler)

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        run()
