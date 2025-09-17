from DATABASE_COMMUNICATION import DBC
import sys, os
sys.path.append(os.path.relpath(os.path.join('../communication_protocols/python')))
sys.path.append(os.path.relpath(os.path.join('..')))
from ghost_protocol.utils import get_configuration
import ipaddress
import numpy as np

class GD:
    #initialization
    def __init__(self, config):
        self.name = config.get("Database", "name")
        self.user = config.get("Database", "user")
        self.password = config.get("Database", "password")
        self.host = config.get("Database", "host")
        self.port = config.get("Database", "port")
    #GET DEVICES
    def get_devices(self):
        #connect to the database with the context_reasoning user
        ps_cur, conn = DBC(self.name, self.user, self.password, self.host, self.port).connect()
        ps_cur.execute("SELECT IP4_DEVICE, DEVICE_INFO_ID, 'IP' FROM DEVICE_INFO WHERE INTERFACE_TYPE = '0';")
        ip_devices = ps_cur.fetchall()
        ip_devices = np.asarray(ip_devices)
        for i, ip in enumerate(ip_devices):
            ip[0] = str(ipaddress.IPv4Address(int(ip[0])).compressed)

        ps_cur.execute("SELECT BLUETOOTH_DEVICE, DEVICE_INFO_ID, 'Bluetooth' FROM DEVICE_INFO WHERE INTERFACE_TYPE = '1';")
        bt_devices = ps_cur.fetchall()
        bt_devices = np.asarray(bt_devices)
        for i, bt in enumerate(bt_devices):
            bt[0] = self.int_to_mac(int(bt[0]))

        ps_cur.execute("SELECT ZWAVE_DEVICE_NODE_ID, DEVICE_INFO_ID, 'Z-Wave' FROM DEVICE_INFO WHERE INTERFACE_TYPE = '4';")
        zw_devices = ps_cur.fetchall()
        zw_devices = np.asarray(zw_devices)
        for i, zw in enumerate(zw_devices):
            zw[0] = format(int(zw[0]), 'x')

        ps_cur.execute("SELECT TVES_RF869, DEVICE_INFO_ID, 'RF869' FROM DEVICE_INFO WHERE INTERFACE_TYPE = '2';")
        rf_devices = ps_cur.fetchall()
        rf_devices = np.asarray(rf_devices)
        for i, rf in enumerate(rf_devices):
            rf[0] = format(int(rf[0]),'06x')

        ps_cur.execute("SELECT ZIG_BEE_DEVICE, DEVICE_INFO_ID, 'Zigbee' FROM DEVICE_INFO WHERE INTERFACE_TYPE = '3';")
        zb_devices = ps_cur.fetchall()
        zb_devices = np.asarray(zb_devices)
        for i, zb in enumerate(zb_devices):
            zb[0] = "{0:#0{1}x}".format(int(zb[0]),10)

        DBC(self.name, self.user, self.password, self.host, self.port).disconnect(conn)     

        return(ip_devices, bt_devices, zw_devices, rf_devices, zb_devices)

    def get_all(self):
        #connect to the database with the context_reasoning user
        ps_cur, conn = DBC(self.name, self.user, self.password, self.host, self.port).connect()

        ps_cur.execute("SELECT * FROM DEVICE_INFO WHERE INTERFACE_TYPE = '0';")
        all_devices = ps_cur.fetchall()
        ps_cur.execute("SELECT * FROM DEVICE_INFO WHERE INTERFACE_TYPE = '1';")
        all_devices = all_devices + ps_cur.fetchall()
        ps_cur.execute("SELECT * FROM DEVICE_INFO WHERE INTERFACE_TYPE = '4';")
        all_devices = all_devices + ps_cur.fetchall()
        ps_cur.execute("SELECT * FROM DEVICE_INFO WHERE INTERFACE_TYPE = '2';")
        all_devices = all_devices + ps_cur.fetchall()
        ps_cur.execute("SELECT * FROM DEVICE_INFO WHERE INTERFACE_TYPE = '3';")
        all_devices = all_devices + ps_cur.fetchall()

        DBC(self.name, self.user, self.password, self.host, self.port).disconnect(conn)

        return(all_devices)     
    
    def new_devices(self, old_devices, devices, new_devices):
        for i, dev in enumerate(devices):
            # a flag for checking new devices
            flag = 1
            for old_dev in old_devices:
                if dev == old_dev:
                    flag = 0
                    break
            #if the flag remained 1 after the inner loop append the new device
            if flag:
                new_devices.append(dev)
        return(new_devices)

    @staticmethod
    def int_to_mac(macint):
        return ':'.join(['{}{}'.format(a, b)
                         for a, b
                         in zip(*[iter('{:012x}'.format(macint))]*2)])
