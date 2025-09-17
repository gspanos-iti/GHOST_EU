import unittest
import psycopg2
from ghost_protocol import Communicator
from ghost_protocol.inter_pb2 import BLUETOOTH, InterfacesInfo, IP4, ZWAVE, TVES_RF869
from ghost_protocol import INTER_REQUEST_ADDRESS
from ghost_ndfa import NDFA_PUBSUB_ADDRESS
from ghost_ndfa.rf_packets_processor import RfPacketsProcessor
from ghost_protocol.utils import get_configuration
from uuid import uuid4
import time
from threading import Lock, Thread
import psycopg2
from psycopg2.extras import Json

class TestRFProcessor(unittest.TestCase):

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

    def test_01_run_rf_processor(self):


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
        interface_info.type = TVES_RF869
        interface_info.id.value = str(uuid4())
        interface_info.description = "RF869 Interface"
        interface_info.started = False
        interface_info.tshark = False
        interface_info.config.pcap_path = "../../pcaps/rf_short"

        self.rf = RfPacketsProcessor(config, communicator, INTERFACESINFO.interfaces[0], self.conn,  self.ps_cur,  self.lock)

        t = Thread(target=self.rf.run, args=[True])
        t.setDaemon(True)

        print("\nStart RF869 processor and wait for 30 secs to process all pcap files")
        t.start()
        time.sleep(30)
        t._Thread__stop()
        print("\nRF869 processor stopped")


    def test_02_number_rf_packets(self):

        self.ps_cur.execute("select count(*) from rf869_packets")
        row = self.ps_cur.fetchone()
        no_rf_packets = int(row[0])
        self.assertEqual(no_rf_packets,400)


    def test_03_number_rf_flows(self):

        self.ps_cur.execute("select count(*) from rf869_flows")
        row = self.ps_cur.fetchone()
        no_rf_flows = int(row[0])
        self.assertEqual(no_rf_flows, 395)


    def test_04_first_rf_packet(self):


        self.ps_cur.execute("select * from rf869_packets where id=1")
        row = self.ps_cur.fetchone()
        p1_data = row[2]
        self.assertEqual(p1_data,{"type": "40", "length": 4, "time": 1506083339.431133, "data": "", "address": "000535"})

    def test_05_last_rf_packet(self):


        self.ps_cur.execute("select * from rf869_packets")
        rows = self.ps_cur.fetchall()
        p_last_data = rows[-1][2]
        self.assertEqual(p_last_data,{"type": "40", "length": 4, "time": 1506095984.432409, "data": "", "address": "0004ff"})


    def test_06_first_rf_flow(self):


        self.ps_cur.execute("select * from rf869_flows where id=1")
        row = self.ps_cur.fetchone()
        b1_data = row[2]
        self.assertEqual(b1_data,{"number_of_packets": 1, "start_time": 1506083339.431133, "min_size": 4, "stop_time": 1506083339.431133, "address": "000535", "duration": 0.0, "max_size": 4, "average_size": 4.0})


    def test_07_last_rf_flow(self):


        self.ps_cur.execute("select * from rf869_flows")
        rows = self.ps_cur.fetchall()
        b_last_data = rows[-1][2]
        self.assertEqual(b_last_data, {"number_of_packets": 1, "start_time": 1506095928.17226, "min_size": 4, "stop_time": 1506095928.17226, "address": "000352", "duration": 0.0, "max_size": 4, "average_size": 4.0})


suite = unittest.TestLoader().loadTestsFromTestCase(TestRFProcessor)
unittest.TextTestRunner(verbosity=2).run(suite)
