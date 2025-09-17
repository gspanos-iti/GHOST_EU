import unittest
import psycopg2
from ghost_protocol import Communicator
from ghost_protocol.inter_pb2 import BLUETOOTH, InterfacesInfo, IP4, ZWAVE, TVES_RF869
from ghost_protocol import INTER_REQUEST_ADDRESS
from ghost_ndfa import NDFA_PUBSUB_ADDRESS
from ghost_ndfa.bt_packets_processor import BtPacketsProcessor
from ghost_protocol.utils import get_configuration
from uuid import uuid4
import time
from threading import Lock, Thread
import psycopg2
from psycopg2.extras import Json

class TestBTProcessor(unittest.TestCase):

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


    def test_01_run_bt_processor(self):


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
        interface_info.type = BLUETOOTH
        interface_info.id.value = str(uuid4())
        interface_info.description = "BT Interface"
        interface_info.started = False
        interface_info.tshark = False
        interface_info.config.pcap_path = "../../pcaps/bt_short"

        self.bt = BtPacketsProcessor(config, communicator, INTERFACESINFO.interfaces[0], self.conn,  self.ps_cur,  self.lock)

        t = Thread(target=self.bt.run, args=[True])
        t.setDaemon(True)

        print("\nStart BT processor and wait for 30 secs to process all pcap files")
        t.start()
        time.sleep(30)
        t._Thread__stop()
        print("\nBT processor stopped")


    def test_02_number_bt_packets(self):


        self.ps_cur.execute("select count(*) from bt_packets")
        row = self.ps_cur.fetchone()
        no_bt_packets = int(row[0])
        self.assertEqual(no_bt_packets,67)


    def test_03_number_bt_batches(self):

        self.ps_cur.execute("select count(*) from bt_batches")
        row = self.ps_cur.fetchone()
        no_bt_flows = int(row[0])
        self.assertEqual(no_bt_flows, 10)


    def test_04_first_bt_packet(self):


        self.ps_cur.execute("select * from bt_packets where id=1")
        row = self.ps_cur.fetchone()
        p1_data = row[2]
        self.assertEqual(p1_data,{"direction": "0x00000000", "param_length": 5, "bt_type": "0x00000001", "taxonomy": "man", "opcode_ocf": 1, "length": 9, "opcode": 1025, "time": 1541080037.055994, "opcode_ogf": 1})


    def test_05_last_bt_packet(self):


        self.ps_cur.execute("select * from bt_packets")
        rows = self.ps_cur.fetchall()
        p_last_data = rows[-1][2]
        self.assertEqual(p_last_data,{"direction": "0x00000001", "bt_type": "0x00000004", "taxonomy": "man", "length": 7, "event_code": 15, "time": 1541080071.339401})


    def test_06_first_bt_batch(self):


        self.ps_cur.execute("select * from bt_batches where id=1")
        row = self.ps_cur.fetchone()
        b1_data = row[2]
        self.assertEqual(b1_data,{"number_of_packets": 9, "taxonomy": "man", "start_time": 1541080037.055994, "min_size": 7, "batch_id": "144444444", "stop_time": 1541080039.046992, "duration": 1.9909980297088623, "max_size": 258, "average_size": 202.44444444444446})


    def test_07_last_bt_batch(self):


        self.ps_cur.execute("select * from bt_batches")
        rows = self.ps_cur.fetchall()
        b_last_data = rows[-1][2]
        self.assertEqual(b_last_data,{"number_of_packets": 4, "taxonomy": "man", "start_time": 1541080069.513891, "min_size": 7, "batch_id": "4414", "stop_time": 1541080069.515482, "duration": 0.0015909671783447266, "max_size": 258, "average_size": 74.0})



suite = unittest.TestLoader().loadTestsFromTestCase(TestBTProcessor)
unittest.TextTestRunner(verbosity=2).run(suite)
