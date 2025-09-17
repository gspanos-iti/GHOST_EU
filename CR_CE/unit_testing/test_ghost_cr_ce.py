import unittest
import numpy as np
import sys,os
sys.path.append(os.path.relpath(os.path.join('../CR_CE')))
sys.path.append(os.path.relpath(os.path.join('../communication_protocols/python')))
from ghost_cr_ce.FEATURE_EXTRACTION import FEATURE_EXTRACTION
from ghost_cr_ce.communication_events import CR_CE
from ghost_protocol.utils import get_configuration
from ghost_cr_ce.DATABASE_COMMUNICATION import DBC

#get configuration
config = get_configuration('cr_ce.ini')
db_name = config.get("Database", "name")
db_user = config.get("Database", "user")
db_password = config.get("Database", "password")
db_host = config.get("Database", "host")
db_port = config.get("Database", "port")

class Test_CR_CE(unittest.TestCase):

    def test_FEATURE_EXTRACTION_IP(self):  
        actual = [[61, 80, 63.0, 64.0, 69.4, 77.5, 7.793587107359486, 14.5, 4.601478576660156e-05, 96299321.19722795, 0.0005830526351928711, 
                    0.00067901611328125, 1851856.2989274426, 0.0757, 12110368.506815, 0.07515, 80, 80]]
        result = FEATURE_EXTRACTION(config).FEATURE_EXTRACTION_IP(1650000000, 1500000000, ["192.168.1.1"], [])
        for ac, res in zip(result, actual):
            for vl1, vl2 in zip(ac, res):
                self.assertAlmostEquals(vl1, vl2, places = 3)
      
    def test_FEATURE_EXTRACTION_BT(self):  
        actual = [[6, 23, 14.0, 17.0, 17.128544423440452, 21, 3.628614221782447, 7.0, 1.9073486328125e-06, 108919373.80551195, 8.58306884765625e-05,
                    0.0012229681015014648, 283029.558139, 0.05990302562713623, 5048555.146865, 0.05981719493865967, 529, 529]]
        result = FEATURE_EXTRACTION(config).FEATURE_EXTRACTION_BT(1650000000, 1500000000, ["00:12:a1:b0:78:14"], [])
        for ac, res in zip(actual, result):
            for vl1, vl2 in zip(ac, res):
                self.assertAlmostEquals(vl1, vl2, places = 3)

    def test_FEATURE_EXTRACTION_ZW(self):  
        actual = [[93, 168, 99.0, 168.0, 147.98837209302326, 168.0, 31.395264857768815, 69.0, 0.009704113006591797, 89583839.598258, 0.07155, 
                    0.3756, 1725124.2001, 20.5231665, 11455291.023987, 20.451613, 86, 86]]
        result = FEATURE_EXTRACTION(config).FEATURE_EXTRACTION_ZW(1650000000, 1500000000, ["a"], [])
        for ac, res in zip(result, actual):
            for vl1, vl2 in zip(ac, res):
                self.assertAlmostEquals(vl1, vl2, places = 3)
    
    def test_FEATURE_EXTRACTION_RF(self):  
        actual = [[4, 6, 4.0, 4.0, 4.030576789437109, 4.0, 0.24539486307161545, 0.0, 59.41281509399414, 88937299.62847, 59.58015811443329, 
                    59.61732244491577, 104227.251269, 59.69218951463699, 2841025.522366, 0.11203140020370483, 1439, 0]]
        result = FEATURE_EXTRACTION(config).FEATURE_EXTRACTION_RF(1650000000, 1500000000, ["0003e0"], [])
        for ac, res in zip(result, actual):
            for vl1, vl2 in zip(ac, res):
                self.assertAlmostEquals(vl1, vl2, places = 3)

    def test_FEATURE_EXTRACTION_ZB(self):  
        actual = [[33, 53, 35.75, 36.5, 39.666666666666664, 43.0, 6.459274125025367, 7.25, 0.0, 142361987.612306, 0.0, 
                    0.0, 3061237.75626, 0.015, 20135301.06348, 0.015, 48, 48]]
        result = FEATURE_EXTRACTION(config).FEATURE_EXTRACTION_ZB(1650000000, 1500000000, ["0x0000172c"], [])
        for ac, res in zip(result, actual):
            for vl1, vl2 in zip(ac, res):
                self.assertAlmostEquals(vl1, vl2, places =3)
        
    def test_CR_events_IP(self):  
        #drop event table
        ps_cur, conn = DBC(db_name, db_user, db_password, db_host, db_port).connect()
        ps_cur.execute("TRUNCATE TABLE EVENTS;")
        DBC(db_name, db_user, db_password, db_host, db_port).disconnect(conn)
        
        actual = [[11.0, 22.0, 11.0, 11.0, 13.2, 11.0, 4.3999999999999995, 0.0, 0.0, 0.00899982452392578, 
                    0.0, 0.000999927520751953, 0.0009999752044677727, 0.000999927520751953, 0.0016970231883994228, 0.0, 25.0]]
        result = CR_CE(config).CR_events_IP(1650000000, 1500000000, [], ["192.168.1.1"])
        for ac, res in zip(result, actual):
            for vl1, vl2 in zip(ac, res):
                self.assertAlmostEqual(vl1, vl2)

    def test_CR_events_ZW(self):  
        #delete event table
        ps_cur, conn = DBC(db_name, db_user, db_password, db_host, db_port).connect()
        ps_cur.execute("TRUNCATE TABLE EVENTS;")
        DBC(db_name, db_user, db_password, db_host, db_port).disconnect(conn)
        
        actual = [[1.0, 11.0, 2.0, 4.0, 4.6, 5.0, 3.4985711369071804, 3.0, 0.0, 1.64531254768372, 0.0743480324745178,
                    1.05339233080546, 0.8340829809506737, 1.39736199378967, 0.6776968139556387, 3.0, 5.0]]
        result = CR_CE(config).CR_events_BT_ZW_RF_ZB(1650000000, 1500000000, [], ["a"], "zw")
        for ac, res in zip(result, actual):
            for vl1, vl2 in zip(ac, res):
                self.assertAlmostEqual(vl1, vl2)

    def test_CR_events_BT(self):  
        #delete event table
        ps_cur, conn = DBC(db_name, db_user, db_password, db_host, db_port).connect()
        ps_cur.execute("TRUNCATE TABLE EVENTS;")
        DBC(db_name, db_user, db_password, db_host, db_port).disconnect(conn)
        
        actual = [[0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]]
        result = CR_CE(config).CR_events_BT_ZW_RF_ZB(1650000000, 1500000000, [], ["00:12:a1:b0:78:14"], "bt")
        for ac, res in zip(result, actual):
            for vl1, vl2 in zip(ac, res):
                self.assertAlmostEqual(vl1, vl2)
    
    def test_CR_events_RF(self):  
        #delete event table
        ps_cur, conn = DBC(db_name, db_user, db_password, db_host, db_port).connect()
        ps_cur.execute("TRUNCATE TABLE EVENTS;")
        DBC(db_name, db_user, db_password, db_host, db_port).disconnect(conn)
        
        actual = [[1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0]]
        result = CR_CE(config).CR_events_BT_ZW_RF_ZB(1650000000, 1500000000, [], ["0003e0"], "rf")
        for ac, res in zip(result, actual):
            for vl1, vl2 in zip(ac, res):
                self.assertAlmostEqual(vl1, vl2)

    def test_CR_events_ZB(self):  
        #delete event table
        ps_cur, conn = DBC(db_name, db_user, db_password, db_host, db_port).connect()
        ps_cur.execute("TRUNCATE TABLE EVENTS;")
        DBC(db_name, db_user, db_password, db_host, db_port).disconnect(conn)
        
        actual = [[1.0, 4.0, 1.75, 2.5, 2.5, 3.25, 1.118033988749895, 1.5, 0.0, 0.147848129272461, 0.011616110801696774, 
                    0.02859604358673095, 0.05126005411148073, 0.06823998689651489, 0.057723041379148285, 1.5, 4.0]]
        result = CR_CE(config).CR_events_BT_ZW_RF_ZB(1650000000, 1500000000, [], ["0x0000172c"], "zb")
        for ac, res in zip(result, actual):
            for vl1, vl2 in zip(ac, res):
                self.assertAlmostEqual(vl1, vl2)                


suite = unittest.TestLoader().loadTestsFromTestCase(Test_CR_CE)
unittest.TextTestRunner(verbosity=2).run(suite)



