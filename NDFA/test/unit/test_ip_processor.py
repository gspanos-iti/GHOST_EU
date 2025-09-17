import unittest
import psycopg2
from ghost_protocol import Communicator
from ghost_protocol.inter_pb2 import BLUETOOTH, InterfacesInfo, IP4, ZWAVE, TVES_RF869
from ghost_protocol import INTER_REQUEST_ADDRESS
from ghost_ndfa import NDFA_PUBSUB_ADDRESS
from ghost_ndfa.ip_packets_processor import IpPacketsProcessor
from ghost_protocol.utils import get_configuration
from uuid import uuid4
import time
from threading import Lock, Thread
import psycopg2
from psycopg2.extras import Json


class TestIpProcessor(unittest.TestCase):

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

    def setUp(self):
        self.conn = self.connect_to_db()
        self.ps_cur = self.conn.cursor()
        self.lock = Lock()
        pass

    def tearDown(self):
        # Here you can make the cleanup for the next test.
        self.conn.close()
        pass
    
    def test_01_run_ip_processor(self):

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
        interface_info.type = IP4
        interface_info.id.value = str(uuid4())
        interface_info.description = "ETH0 Interface"
        interface_info.started = False
        interface_info.tshark = False
        interface_info.address = "127.0.0.1"
        interface_info.config.pcap_path = "../../pcaps/ip_short/"

        ip = IpPacketsProcessor(config, communicator, INTERFACESINFO.interfaces[0], self.conn,  self.ps_cur,  self.lock)

        t = Thread(target=ip.run, args=[True])
        t.setDaemon(True)

        print("\nStart IP processor and wait for 30 secs to process all pcap files")
        t.start()
        time.sleep(30)
        t._Thread__stop()
        print("\nIP processor stopped")

    def test_02_number_ip_packets(self):


        self.ps_cur.execute("select count(*) from ipv4_packets")
        row =  self.ps_cur.fetchone()
        no_ip_packets = int(row[0])
        self.assertEqual(no_ip_packets,45)


    def test_03_number_ip_flows(self):

        self.ps_cur.execute("select count(*) from ipv4_flows")
        row =  self.ps_cur.fetchone()
        no_ip_flows = int(row[0])
        self.assertEqual(no_ip_flows, 6)


    def test_04_first_ip_packet(self):


        self.ps_cur.execute("select * from ipv4_packets where id=1")
        row =  self.ps_cur.fetchone()
        p1_data = row[2]
        self.assertEqual(p1_data,{"dst_mac": "b8:27:eb:ab:c1:05", "src_mac": "18:fe:34:d2:67:4c", "src_ip": "192.168.1.27", "length": 44, "options": "'\\x02\\x04\\x05\\xb4'", "flags": 2, "time": 1541080064.501603, "dport": 81, "dst_ip": "192.168.1.1", "sport": 9341, "data": "''", "id": 2440, "transport": "TCP"})


    def test_05_last_ip_packet(self):


        self.ps_cur.execute("select * from ipv4_packets")
        rows =  self.ps_cur.fetchall()
        p_last_data = rows[-1][2]
        self.assertEqual(p_last_data,{"dst_mac": "b8:27:eb:ab:c1:05", "src_mac": "18:fe:34:d2:67:4c", "src_ip": "192.168.1.27", "length": 76, "time": 1541080148.642089, "dport": 123, "dst_ip": "129.6.15.27", "sport": 8888, "data": "'\\xe3\\x00\\x06\\xec\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x001N14\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'", "id": 2464, "transport": "UDP"})




    def test_06_first_ip_flow(self):


        self.ps_cur.execute("select * from ipv4_flows where id=1")
        row =  self.ps_cur.fetchone()
        f1_data = row[2]
        #self.assertEqual(f1_data, {"max_iat_a": "120", "min_load_a": "0", "min_load_b": "0", "max_iat_b": "0", "tb_b": "0", "tb_a": "0", "sfp_a": "0", "sfp_b": "0", "bytes_a": "0", "min_iat_b": "0", "min_iat_a": "120", "port_b": "9341", "port_a": "81", "stdv_iat_b": "0", "mac_a": "b8:27:eb:ab:c1:05", "mac_b": "18:fe:34:d2:67:4c", "stdv_iat_a": "0", "ts_end": 1541080064.502, "prot": "No_Payload", "f4b_a": "00000000", "mean_iat_b": "0", "mean_iat_a": "120", "f4b_b": "00000000", "status": "alive", "max_load_b": "0", "mean_load_a": "0", "mean_load_b": "0", "max_load_a": "0", "tran_prot": "6", "stdv_load_a": "0", "stdv_load_b": "0", "ip_b": "192.168.1.27", "ip_a": "192.168.1.1", "packets_b": "1", "packets_a": "1", "bytes_b": "0", "ts_start": 1541080064.502})
        self.assertEqual(f1_data, {u'max_iat_a': u'120', u'min_load_a': u'0', u'min_load_b': u'0', u'max_iat_b': u'0', u'f4b_a': u'00000000',
         u'tb_a': u'0', u'sfp_a': u'0', u'sfp_b': u'0', u'min_iat_b': u'0', u'min_iat_a': u'120', u'port_b': u'9341',
         u'port_a': u'81', u'stdv_iat_b': u'0', u'mac_a': u'b8:27:eb:ab:c1:05', u'mac_b': u'18:fe:34:d2:67:4c',
         u'stdv_iat_a': u'0', u'ts_end': 1541080064.502, u'prot': u'No_Payload', u'tb_b': u'0', u'mean_iat_b': u'0',
         u'mean_iat_a': u'120', u'bytes_a': u'0', u'status': u'expired', u'max_load_b': u'0', u'mean_load_a': u'0',
         u'mean_load_b': u'0', u'max_load_a': u'0', u'tran_prot': u'6', u'stdv_load_a': u'0', u'stdv_load_b': u'0',
         u'ip_b': u'192.168.1.27', u'ip_a': u'192.168.1.1', u'f4b_b': u'00000000', u'packets_b': u'1',
         u'packets_a': u'1', u'bytes_b': u'0', u'ts_start': 1541080064.502})


    def test_07_last_ip_flow(self):


        self.ps_cur.execute("select * from ipv4_flows")
        rows =  self.ps_cur.fetchall()
        f_last_data = rows[-1][2]
        self.assertEqual(f_last_data,{u'max_iat_a': u'217284', u'min_load_a': u'0', u'min_load_b': u'0', u'max_iat_b': u'109634', u'f4b_a': u'48545450', u'tb_a': u'336', u'sfp_a': u'168', u'sfp_b': u'52', u'min_iat_b': u'0', u'min_iat_a': u'52', u'port_b': u'25855', u'port_a': u'81', u'stdv_iat_b': u'47166', u'mac_a': u'b8:27:eb:ab:c1:05', u'mac_b': u'18:fe:34:d2:67:4c', u'stdv_iat_a': u'86293', u'ts_end': 1541080070.931, u'prot': u'HTTP_NonStandard', u'tb_b': u'52', u'mean_iat_b': u'27947', u'mean_iat_a': u'44742', u'bytes_a': u'336', u'status': u'expired', u'max_load_b': u'52', u'mean_load_a': u'67', u'mean_load_b': u'13', u'max_load_a': u'168', u'tran_prot': u'6', u'stdv_load_a': u'76', u'stdv_load_b': u'23', u'ip_b': u'192.168.1.27', u'ip_a': u'192.168.1.1', u'f4b_b': u'47455420', u'packets_b': u'4', u'packets_a': u'5', u'bytes_b': u'52', u'ts_start': 1541080070.596})



suite = unittest.TestLoader().loadTestsFromTestCase(TestIpProcessor)
unittest.TextTestRunner(verbosity=2).run(suite)
