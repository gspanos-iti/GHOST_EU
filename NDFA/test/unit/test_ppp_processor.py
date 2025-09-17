import unittest
import psycopg2
from ghost_protocol import Communicator
from ghost_protocol.inter_pb2 import BLUETOOTH, InterfacesInfo, IP4, ZWAVE, TVES_RF869, ZIGBEE, PPP
from ghost_protocol import INTER_REQUEST_ADDRESS
from ghost_ndfa import NDFA_PUBSUB_ADDRESS
from ghost_ndfa.ppp_packets_processor import PppPacketsProcessor
from ghost_protocol.utils import get_configuration
from uuid import uuid4
import time
from threading import Lock, Thread
import psycopg2
from psycopg2.extras import Json

class TestPppProcessor(unittest.TestCase):


		
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


    def test_01_run_ppp_processor(self):


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
        interface_info.type = PPP
        interface_info.id.value = str(uuid4())
        interface_info.description = "PPP Interface"
        interface_info.started = False
        interface_info.tshark = False
        interface_info.address = "127.0.0.1"
        interface_info.config.pcap_path = "../../pcaps/ppp_short"


        self.ppp = PppPacketsProcessor(config, communicator, INTERFACESINFO.interfaces[0],  self.conn,  self.ps_cur,  self.lock)

        t = Thread(target=self.ppp.run, args=[True])
        t.setDaemon(True)

        print("\nStart PPP processor and wait for 30 secs to process all pcap files")
        t.start()
        time.sleep(30)
        t._Thread__stop()
        print("\nPPP processor stopped")


    def test_02_number_ppp_packets(self):

        self.ps_cur.execute("select count(*) from ppp_packets")
        row = self.ps_cur.fetchone()
        no_ppp_packets = int(row[0])
        self.assertEqual(no_ppp_packets,70)


    def test_03_number_ppp_flow(self):

        self.ps_cur.execute("select count(*) from ppp_flows")
        row = self.ps_cur.fetchone()
        no_ppp_flows = int(row[0])
        self.assertEqual(no_ppp_flows, 18)


    def test_04_first_ppp_packet(self):

        self.ps_cur.execute("select * from ppp_packets where id=1")
        row = self.ps_cur.fetchone()
        p1_data = row[2]
        self.assertEqual(p1_data,{u'src_ip': u'47.59.127.15', u'length': 92, u'time': 1551942785.497853, u'dport': 123, u'dst_ip': u'130.206.3.166', u'sport': 123, u'data': u'\'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x08\\x00E\\xb8\\x00Lcx@\\x00@\\x11\\xa1\\xb2/;\\x7f\\x0f\\x82\\xce\\x03\\xa6\\x00{\\x00{\\x008\\x97\\x16#\\x02\\x06\\xed\\x00\\x00\\x19Z\\x00\\x00\\x18"\\\\\\xf6\\x18\\xe4\\xe0+A=\\xebp\\x19\\x9d\\xe0+B\\xbf\\xc0\\x89LD\\xe0+B\\xbf\\xd6Ie\\x10\\xe0+C\\x01\\x7fl\\n^\'', u'transport': 17})


    def test_05_last_ppp_packet(self):

        self.ps_cur.execute("select * from ppp_packets")
        rows = self.ps_cur.fetchall()
        p_last_data = rows[-1][2]
        self.assertEqual(p_last_data,{u'src_ip': u'172.217.168.164', u'length': 100, u'time': 1551942950.479343, u'dst_ip': u'47.59.127.15', u'data': u'\'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x08\\x00E\\x00\\x00T\\x00\\x00\\x00\\x009\\x01}\\xe1\\xac\\xd9\\xa8\\xa4/;\\x7f\\x0f\\x00\\x00\\xa4\\xf4\\x00\\x00"N%\\xc5\\x80\\\\\\xc7\\x96\\r\\x00\\x0f\\x00\\x00\\x00\\x08\\x00\\x00\\x00\\x07\\x00\\x00\\x00\\x02\\x00\\x00\\x00w\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\\\\\xd9\\x7ft\\x00\\x00\\x00\\x00\\xf4\\xa6\\x02\\x00\\xa0\\xb0\\x02\\x00\\xf8\\xa6\\x02\\x00\\xb0\\xb7\\x02\\x00\'', u'transport': 1})


    def test_06_first_ppp_flow(self):

        self.ps_cur.execute("select * from ppp_flows where id=1")
        row = self.ps_cur.fetchone()
        b1_data = row[2]
        self.assertEqual(b1_data,{u'max_iat_a': u'0', u'min_load_a': u'48', u'min_load_b': u'48', u'max_iat_b': u'786875', u'f4b_a': u'230206ed', u'tb_a': u'48', u'sfp_a': u'48', u'sfp_b': u'48', u'min_iat_b': u'786875', u'min_iat_a': u'0', u'port_b': u'123', u'port_a': u'123', u'stdv_iat_b': u'0', u'mac_a': u'', u'mac_b': u'', u'stdv_iat_a': u'0', u'ts_end': 1551942786.285, u'prot': u'NTP', u'tb_b': u'48', u'mean_iat_b': u'786875', u'mean_iat_a': u'0', u'bytes_a': u'48', u'status': u'expired', u'max_load_b': u'48', u'mean_load_a': u'48', u'mean_load_b': u'48', u'max_load_a': u'48', u'tran_prot': u'17', u'stdv_load_a': u'0', u'stdv_load_b': u'0', u'ip_b': u'47.59.127.15', u'ip_a': u'130.206.3.166', u'f4b_b': u'240106ec', u'packets_b': u'1', u'packets_a': u'1', u'bytes_b': u'48', u'ts_start': 1551942785.498})


    def test_07_last_ppp_flow(self):

        self.ps_cur.execute("select * from ppp_flows")
        rows = self.ps_cur.fetchall()
        b_last_data = rows[-1][2]
        self.assertEqual(b_last_data,{u'max_iat_a': u'0', u'min_load_a': u'0', u'min_load_b': u'0', u'max_iat_b': u'0', u'f4b_a': u'00000000', u'tb_a': u'0', u'sfp_a': u'0', u'sfp_b': u'0', u'min_iat_b': u'0', u'min_iat_a': u'0', u'port_b': u'45533', u'port_a': u'8117', u'stdv_iat_b': u'0', u'mac_a': u'', u'mac_b': u'', u'stdv_iat_a': u'0', u'ts_end': 1551942880.438, u'prot': u'No_Payload', u'tb_b': u'0', u'mean_iat_b': u'0', u'mean_iat_a': u'0', u'bytes_a': u'0', u'status': u'expired', u'max_load_b': u'0', u'mean_load_a': u'0', u'mean_load_b': u'0', u'max_load_a': u'0', u'tran_prot': u'6', u'stdv_load_a': u'0', u'stdv_load_b': u'0', u'ip_b': u'78.128.112.166', u'ip_a': u'47.59.127.15', u'f4b_b': u'00000000', u'packets_b': u'1', u'packets_a': u'0', u'bytes_b': u'0', u'ts_start': 1551942880.438})
	

suite = unittest.TestLoader().loadTestsFromTestCase(TestPppProcessor)
unittest.TextTestRunner(verbosity=2).run(suite)
