import unittest
import psycopg2
from ghost_protocol import Communicator
from ghost_protocol.inter_pb2 import BLUETOOTH, InterfacesInfo, IP4, ZWAVE, TVES_RF869
from ghost_protocol import INTER_REQUEST_ADDRESS
from ghost_ndfa import NDFA_PUBSUB_ADDRESS
from ghost_ndfa.zw_packets_processor import ZwPacketsProcessor
from ghost_protocol.utils import get_configuration
from uuid import uuid4
import time
from threading import Lock, Thread
import psycopg2
from psycopg2.extras import Json

class TestZWProcessor(unittest.TestCase):

    def setUp(self):
        self.conn = self.connect_to_db()
        self.ps_cur = self.conn.cursor()
        self.lock = Lock()
        pass

    def tearDown(self):
        # Here you can make the cleanup for the next test.
        self.conn.close()
        pass

    def connect_to_db(self):
        config = get_configuration("./config.template.ini")

        params = {
            'database': config.get('PostgreSQL', 'database'),
            'user': config.get('PostgreSQL', 'user'),
            'password': config.get('PostgreSQL', 'pass'),
            'host': config.get('PostgreSQL', 'host'),
            'port': config.get('PostgreSQL', 'port')
        }
        conn = psycopg2.connect(**params)
        return conn

    def test_01_run_zw_processor(self):

        config = get_configuration("./config.template.ini")

        communicator = Communicator(
            None,
            None,
            NDFA_PUBSUB_ADDRESS,
            [("gateway", INTER_REQUEST_ADDRESS)],
            [])

        INTERFACESINFO = InterfacesInfo()

        # Interface List
        # mockup of interfaces attached to the gateway
        interface_info = INTERFACESINFO.interfaces.add()
        interface_info.type = ZWAVE
        interface_info.id.value = str(uuid4())
        interface_info.description = "zw Interface"
        interface_info.started = False
        interface_info.tshark = False
        interface_info.config.pcap_path = "../../pcaps/zwave_short"

        self.zw = ZwPacketsProcessor(config, communicator, INTERFACESINFO.interfaces[0], self.conn,  self.ps_cur,  self.lock)

        t = Thread(target=self.zw.run, args=[True])
        t.setDaemon(True)

        print("\nStart ZW processor and wait for 30 secs to process all pcap files")
        t.start()
        time.sleep(30)
        t._Thread__stop()
        print("\nZW processor stopped")


    def test_02_number_zw_packets(self):


        self.ps_cur.execute("select count(*) from zw_packets")
        row = self.ps_cur.fetchone()
        no_zw_packets = int(row[0])
        self.assertEqual(no_zw_packets,44)


    def test_03_number_zw_batches(self):

        self.ps_cur.execute("select count(*) from zw_batches")
        row = self.ps_cur.fetchone()
        no_zw_batches = int(row[0])
        self.assertEqual(no_zw_batches, 30)


    def test_04_first_zw_packet(self):


        self.ps_cur.execute("select * from zw_packets where id=1")
        row = self.ps_cur.fetchone()
        p1_data = row[2]
        self.assertEqual(p1_data,{"text": {"descr": "battery", "vid": "0x013c", "level": "100", "de": "10", "pid": "0x000c", "ptype": "0x0002", "value": "0x64", "instance": "0", "class": "0x0080"}, "dst_zw_addr": "00:06:19:25:27:0a", "length": 99, "time": 1541080126.701895, "src_zw_addr": "0a:01:00:05:80:00", "data": "64653d313020696e7374616e63653d30207669643d3078303133632070747970653d307830303032207069643d30783030306320636c6173733d3078303038302064657363723d62617474657279206c6576656c3d3130302076616c75653d30783634"})


    def test_05_last_zw_packet(self):


        self.ps_cur.execute("select * from zw_packets")
        rows = self.ps_cur.fetchall()
        p_last_data = rows[-1][2]
        self.assertEqual(p_last_data,{"text": {"descr": "battery", "vid": "0x013c", "level": "100", "de": "10", "pid": "0x000c", "ptype": "0x0002", "value": "0x64", "instance": "0", "class": "0x0080"}, "dst_zw_addr": "00:06:19:25:27:0a", "length": 99, "time": 1541080494.32645, "src_zw_addr": "0a:01:00:05:80:00", "data": "64653d313020696e7374616e63653d30207669643d3078303133632070747970653d307830303032207069643d30783030306320636c6173733d3078303038302064657363723d62617474657279206c6576656c3d3130302076616c75653d30783634"})


    def test_06_first_zw_batch(self):


        self.ps_cur.execute("select * from zw_batches where id=1")
        row = self.ps_cur.fetchone()
        b1_data = row[2]
        self.assertEqual(b1_data,{"total_bytes_b": 0, "total_bytes_a": 99, "number_of_packets": 1, "start_time": 1541080126.701895, "min_size": 99, "packets_b": 0, "packets_a": 1, "stop_time": 1541080126.701895, "duration": 0.0, "src_zw_addr": "0a:01:00:05:80:00", "sum_size": 99, "dst_zw_addr": "00:06:19:25:27:0a", "max_size": 99, "average_size": 99.0})


    def test_07_last_zw_batch(self):

        self.ps_cur.execute("select * from zw_batches")
        rows = self.ps_cur.fetchall()
        b_last_data = rows[-1][2]
        self.assertEqual(b_last_data,{"total_bytes_b": 0, "total_bytes_a": 324, "number_of_packets": 2, "start_time": 1541080477.426493, "min_size": 161, "packets_b": 0, "packets_a": 2, "stop_time": 1541080477.498034, "duration": 0.07154107093811035, "src_zw_addr": "0a:01:00:05:31:00", "sum_size": 324, "dst_zw_addr": "00:06:19:25:27:0a", "max_size": 163, "average_size": 162.0})


suite = unittest.TestLoader().loadTestsFromTestCase(TestZWProcessor)
unittest.TextTestRunner(verbosity=2).run(suite)
