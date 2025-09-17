import sys
import argparse
import os
import signal
import time
import logging
import logging.handlers
from threading import Lock, Thread
import psycopg2

import daemon
from lockfile.pidlockfile import PIDLockFile

from ghost_protocol import INTER_REQUEST_ADDRESS
from ghost_protocol.communicator import Communicator
from ghost_protocol.inter_pb2 import BLUETOOTH, InterfacesInfo, IP4, ZWAVE, TVES_RF869, ZIGBEE, PPP
from ghost_protocol.utils import get_configuration

from ghost_ndfa import NDFA_PUBSUB_ADDRESS
from ghost_ndfa.ip_packets_processor import IpPacketsProcessor
from ghost_ndfa.bt_packets_processor import BtPacketsProcessor
from ghost_ndfa.zw_packets_processor import ZwPacketsProcessor
from ghost_ndfa.rf_packets_processor import RfPacketsProcessor
from ghost_ndfa.zb_packets_processor import ZbPacketsProcessor
from ghost_ndfa.ppp_packets_processor import PppPacketsProcessor



# NDFA version number
__version__ = "0.10"


LOG_VALUES = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "notset": logging.NOTSET
}


class Runner:

    def __init__(self, config):
        self._config = config
        self._ip_interfaces = []
        self._bt_interfaces = []
        self._zw_interfaces = []
        self._rf_interfaces = []
        self._zb_interfaces = []
        self._ppp_interfaces = []

        self._ip_interfaces_lock = Lock()
        self._bt_interfaces_lock = Lock()
        self._zw_interfaces_lock = Lock()
        self._rf_interfaces_lock = Lock()
        self._zb_interfaces_lock = Lock()
        self._ppp_interfaces_lock = Lock()

        self._running = True
        self._threads = []
        self._communicator = None

        self.config = config

        # params = {
        #     'database': config.get('PostgreSQL', 'database'),
        #     'user': config.get('PostgreSQL', 'user'),
        #     'password': config.get('PostgreSQL', 'pass'),
        #     'host': config.get('PostgreSQL', 'host'),
        #     'port': config.get('PostgreSQL', 'port')
        # }
        # self.conn = psycopg2.connect(**params)
        # self.ps_cur = self.conn.cursor()
        # self.lock = Lock()

    def run(self):
        params = {
            'database': self.config.get('PostgreSQL', 'database'),
            'user': self.config.get('PostgreSQL', 'user'),
            'password': self.config.get('PostgreSQL', 'pass'),
            'host': self.config.get('PostgreSQL', 'host'),
            'port': self.config.get('PostgreSQL', 'port')
        }
        self.conn = psycopg2.connect(**params)
        self.ps_cur = self.conn.cursor()
        self.lock = Lock()
        self._log_setup()
        logging.info("GHOST NDFA (v2.1) component starting")
        self._get_interfaces()

    def _log_setup(self):
        log_level = LOG_VALUES[self._config.get("Log", "level")]
        formatter = logging.Formatter(
            '%(asctime)s %(levelno)-1s %(process)-5d %(threadName)-10s] %(message)s')

        # Setup file logger
        file_handler = None
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                self._config.get("Log", "filename"),
                maxBytes=int(self._config.get("Log", "maxBytes")),
                backupCount=int(self._config.get("Log", "backupCount")))
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
        # pylint: disable=W0703
        except Exception:
            pass
        # pylint: enable=W0703

        # Setup syslog logger
        syslog_handler = None
        try:
            if self._config.getboolean("Log", "syslog"):
                syslog_handler = logging.handlers.SysLogHandler()
                syslog_handler.setLevel(log_level)
                syslog_handler.setFormatter(formatter)
        # pylint: disable=W0703
        except Exception:
            pass
        # pylint: enable=W0703

        # Setup console logger
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)

        logger = logging.getLogger()
        logger.addHandler(console_handler)
        if file_handler:
            logger.addHandler(file_handler)
        if syslog_handler:
            logger.addHandler(syslog_handler)
        logger.setLevel(log_level)

    def _get_interfaces(self):
        if not self._communicator:
            self._communicator = Communicator(
                None,
                None,
                NDFA_PUBSUB_ADDRESS,
                [("gateway", INTER_REQUEST_ADDRESS)],
                [])
        logging.info("Retrieving interfaces...")
        self._communicator.request("gateway", "interfaces.get", None, # gateway-->sds
                                   self._on_interfaces) #, 3600) # default timeout = 60 sec  
        while self._running:
            time.sleep(1)

    def _on_interfaces(self, data):
        #print data
        if data is None and self._running:
            logging.error("Failed to retrieve interfaces, retrying...")
            self._communicator.request("gateway", "interfaces.get", None, 
                                       self._on_interfaces)  # gateway-->sds
        else:
            logging.info("Interfaces retrieved.")
            interfaces = InterfacesInfo()
            interfaces.ParseFromString(data)
            self._run_processors(interfaces)

    def _run_processors(self, interfaces):

        for interface in interfaces.interfaces:
            if interface.type == IP4:
                t = Thread(target=self._run_ip_interface, args=[interface])
                t.start()
                self._threads.append(t)
            elif interface.type == BLUETOOTH:
                t = Thread(target=self._run_bt_interface, args=[interface])
                t.start()
                self._threads.append(t)
            elif interface.type == ZWAVE:
                t = Thread(target=self._run_zw_interface, args=[interface])
                t.start()
                self._threads.append(t)
            elif interface.type == TVES_RF869:
                t = Thread(target=self._run_rf_interface, args=[interface])
                t.start()
                self._threads.append(t)
            elif interface.type == ZIGBEE:
                t = Thread(target=self._run_zb_interface, args=[interface])
                t.start()
                self._threads.append(t)
            elif interface.type == PPP:
                t = Thread(target=self._run_ppp_interface, args=[interface])
                t.start()
                self._threads.append(t)


    def _run_ip_interface(self, interface):
        ip = IpPacketsProcessor(self._config, self._communicator, interface, self.conn, self.ps_cur, self.lock)
        self._ip_interfaces_lock.acquire()
        self._ip_interfaces.append(ip)
        self._ip_interfaces_lock.release()
        ip.run(True)

    def _run_bt_interface(self, interface):
        bt = BtPacketsProcessor(self._config, self._communicator, interface, self.conn, self.ps_cur, self.lock)
        self._bt_interfaces_lock.acquire()
        self._bt_interfaces.append(bt)
        self._bt_interfaces_lock.release()
        bt.run(True)

    def _run_zw_interface(self, interface):
        zw = ZwPacketsProcessor(self._config, self._communicator, interface, self.conn, self.ps_cur, self.lock)
        self._zw_interfaces_lock.acquire()
        self._zw_interfaces.append(zw)
        self._zw_interfaces_lock.release()
        zw.run(True)

    def _run_rf_interface(self, interface):
        rf = RfPacketsProcessor(self._config, self._communicator, interface, self.conn, self.ps_cur, self.lock)
        self._rf_interfaces_lock.acquire()
        self._rf_interfaces.append(rf)
        self._rf_interfaces_lock.release()
        rf.run(True)

    def _run_zb_interface(self, interface):
        zb = ZbPacketsProcessor(self._config, self._communicator, interface, self.conn, self.ps_cur, self.lock)
        self._zb_interfaces_lock.acquire()
        self._zb_interfaces.append(zb)
        self._zb_interfaces_lock.release()
        zb.run(True)
		
    def _run_ppp_interface(self, interface):
        ppp = PppPacketsProcessor(self._config, self._communicator, interface, self.conn, self.ps_cur, self.lock)
        self._ppp_interfaces_lock.acquire()
        self._ppp_interfaces.append(ppp)
        self._ppp_interfaces_lock.release()
        ppp.run(True)


    def stop(self):

        for ip in self._ip_interfaces:
            ip.close()

        for bt in self._bt_interfaces:
            bt.close()

        for zw in self._zw_interfaces:
            zw.close()

        for rf in self._rf_interfaces:
            rf.close()

        for zb in self._zb_interfaces:
            zb.close()

        for ppp in self._ppp_interfaces:
            ppp.close()
			
        for t in self._threads:
            t.join()

        self._running = False
        self._communicator.stop()
        #logging.info("Waiting for threads to write last data to db")
        #time.sleep(2)
        self.conn.close()


# pylint: disable=W0613
def signal_handler(signum, frame):
    runner.stop()
# pylint: enable=W0613


if __name__ == '__main__':

    sys.path.append(os.getcwd())

    # parse arguments
    parser = argparse.ArgumentParser(description="The NDFA module.")
    parser.add_argument(
        "--config", "-c",
        help="the path and name of the configuration file",
        required=True)
    parser.add_argument(
        "--version", help="display the version",
        action="version", version="%(prog)s {}".format(__version__))

    if sys.platform.startswith('linux'):
        parser.add_argument(
            "--pidfile", "-p",
            help="path to the PID file when running as daemon (in background)",
            type=str)

    args = parser.parse_args()
    config = get_configuration(args.config)
    global runner
    runner = Runner(config)

    if sys.platform.startswith('linux') and args.pidfile:
        daemon_context = daemon.DaemonContext()
        daemon_context.signal_map = {
            signal.SIGTERM: signal_handler,
            signal.SIGINT: signal_handler,
            signal.SIGQUIT: signal_handler,
            signal.SIGUSR1: signal_handler,
            signal.SIGHUP: signal_handler}

        daemon_context.working_directory = os.getcwd()
        daemon_context.pidfile = PIDLockFile(args.pidfile, timeout=5)
        with daemon_context:
            runner.run()

    else:

        if sys.platform.startswith('linux'):
            signal.signal(signal.SIGQUIT, signal_handler)

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        runner.run()
