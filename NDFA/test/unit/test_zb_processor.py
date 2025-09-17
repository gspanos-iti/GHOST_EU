import unittest
import psycopg2
from ghost_protocol import Communicator
from ghost_protocol.inter_pb2 import BLUETOOTH, InterfacesInfo, IP4, ZWAVE, TVES_RF869, ZIGBEE, PPP
from ghost_protocol import INTER_REQUEST_ADDRESS
from ghost_ndfa import NDFA_PUBSUB_ADDRESS
from ghost_ndfa.zb_packets_processor import ZbPacketsProcessor
from ghost_protocol.utils import get_configuration
from uuid import uuid4
import time
from threading import Lock, Thread
import psycopg2
from psycopg2.extras import Json

class TestZBProcessor(unittest.TestCase):

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


    def test_01_run_zb_processor(self):


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
        interface_info.type = ZIGBEE
        interface_info.id.value = str(uuid4())
        interface_info.description = "ZigBee Interface"
        interface_info.started = True
        interface_info.tshark = False
        interface_info.config.pcap_path = "../../pcaps/zigbee_short"


        self.zb = ZbPacketsProcessor(config, communicator, INTERFACESINFO.interfaces[0], self.conn,  self.ps_cur,  self.lock)

        t = Thread(target=self.zb.run, args=[True])
        t.setDaemon(True)

        print("\nStart ZB processor and wait for 30 secs to process all pcap files")
        t.start()
        time.sleep(30)
        t._Thread__stop()
        print("\nZB processor stopped")


    def test_02_number_zb_packets(self):


        self.ps_cur.execute("select count(*) from zgb_packets")
        row = self.ps_cur.fetchone()
        no_zb_packets = int(row[0])
        self.assertEqual(no_zb_packets,117)


    def test_03_number_zb_batches(self):

        self.ps_cur.execute("select count(*) from zgb_flows")
        row = self.ps_cur.fetchone()
        no_zb_flows = int(row[0])
        self.assertEqual(no_zb_flows, 39)


    def test_04_first_zb_packet(self):

        self.ps_cur.execute("select * from zgb_packets where id=1")
        row = self.ps_cur.fetchone()
        p1_data = row[2]
        self.assertEqual(p1_data,{u'dst_zb_addr': u'0x0000ffff', u'data_length': 23, u'dst_zb_pan': u'0x00001059', u'length': 34, u'src_zb_addr': u'0x00000000', u'time': 1507637905.73687, u'data': u'0800fcff00000000000036000000000000000000000000'})

    def test_05_last_zb_packet(self):

        self.ps_cur.execute("select * from zgb_packets")
        rows = self.ps_cur.fetchall()
        p_last_data = rows[-1][2]
        self.assertEqual(p_last_data,{u'dst_zb_addr': u'0x00000000', u'data_length': 32, u'dst_zb_pan': u'0x00001059', u'length': 43, u'src_zb_addr': u'0x000055b7', u'time': 1507638670.371526, u'data': u'48000000b7550000000001800000000000007f2e6007004b1200b75500000000'})


    def test_06_first_zb_batch(self):

        self.ps_cur.execute("select * from zgb_flows where id=1")
        row = self.ps_cur.fetchone()
        b1_data = row[2]
        self.assertEqual(b1_data,{u'total_bytes_b': 0, u'total_bytes_a': 34, u'dst_zb_addr': u'0x0000ffff', u'number_of_packets': 1, u'start_time': 1507637905.73687, u'min_size': 34, u'packets_b': 0, u'packets_a': 1, u'stop_time': 1507637905.73687, u'src_zb_addr': u'0x00000000', u'duration': 0.0, u'average_size': 34.0, u'max_size': 34, u'sum_size': 34})


    def test_07_last_zb_batch(self):


        self.ps_cur.execute("select * from zgb_flows")
        rows = self.ps_cur.fetchall()
        b_last_data = rows[-1][2]
        self.assertEqual(b_last_data,{u'total_bytes_b': 43, u'total_bytes_a': 36, u'dst_zb_addr': u'0x0000172c', u'number_of_packets': 2, u'start_time': 1507638662.428566, u'min_size': 36, u'packets_b': 1, u'packets_a': 1, u'stop_time': 1507638662.444534, u'src_zb_addr': u'0x00000000', u'duration': 0.01596808433532715, u'average_size': 39.5, u'max_size': 43, u'sum_size': 79})


suite = unittest.TestLoader().loadTestsFromTestCase(TestZBProcessor)
unittest.TextTestRunner(verbosity=2).run(suite)
