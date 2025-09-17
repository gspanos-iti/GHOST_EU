import time
from subprocess import call, check_output
import os.path
from datetime import datetime
import logging
import os
import errno
import socket

import psycopg2
from psycopg2.extras import Json
import dpkt
from dpkt.compat import compat_ord

import uuid, re
import fcntl
import struct

from ghost_ndfa import (NDFA_PUBSUB_ADDRESS, NDFA_ALERT_TOPIC, NDFA_FLOW_TOPIC, NDFA_EXTERNAL_IP_TOPIC,NDFA_NEWDEVICE_TOPIC)

from ghost_protocol.ndfa_pb2 import FileProcessing
from ghost_protocol.inter_pb2 import InterfaceId
from ghost_protocol.ndfa_pb2 import FlowAdded
from ghost_protocol.ndfa_pb2 import NewExternalIp
from ghost_protocol.ndfa_pb2 import NewDevice


class PppPacketsProcessor:

    def __init__(self, config, communicator, interface, conn, ps_cur, lock):

        self.keep_running = True
        self.storage_db = config.get('Storage', 'storage_db')

        self.clear_db_on_startup = config.getboolean(
            'Options', 'clear_db_on_startup')
        self.ip_packets_payload_analysis = config.getboolean(
            'Options', 'ip_packets_payload_analysis')

        self.pcap_path_eth0 = interface.config.pcap_path
        self.root_path = config.get('Paths', 'root_path')

        self.eth0_temp_pcap_path = os.path.join(
            self.root_path, "temp_" + interface.description + ".pcap")
        self.eth0_global_pcap_path = os.path.join(
            self.root_path, "global_" + interface.description + ".pcap")
        self.eth0_aux_pcap_path = os.path.join(
            self.root_path, "aux_" + interface.description + ".pcap")

        self.NDFA_PUBSUB_ADDRESS = NDFA_PUBSUB_ADDRESS
        self.NDFA_ALERT_TOPIC = NDFA_ALERT_TOPIC
        self.NDFA_FLOW_TOPIC = NDFA_FLOW_TOPIC
        self.NDFA_EXTERNAL_IP_TOPIC = NDFA_EXTERNAL_IP_TOPIC
        self.NDFA_NEWDEVICE_TOPIC = NDFA_NEWDEVICE_TOPIC

        self.psql_db_host = config.get('PostgreSQL', 'host')
        self.psql_db_user = config.get('PostgreSQL', 'user')
        self.psql_db_pass = config.get('PostgreSQL', 'pass')
        self.psql_db_database = config.get('PostgreSQL', 'database')
        self.psql_db_port = config.get('PostgreSQL', 'port')

        self.NUM_OF_PCAP_FILES = int(config.get('Files', 'NUM_OF_PCAP_FILES'))
        self.kill_flow_waitime = float(config.get('Time', 'kill_flow_waitime'))
		
        self.silence_alert = float(config.get('Time', 'silence_alert') )
        self.start_time  = time.time()
		
        self.conn = None
        self._communicator = communicator
        self._interface = interface

        self.active_flows = []
		
        self.conn = conn
        self.ps_cur = ps_cur
        self.lock = lock

    @staticmethod
    def safe_create_file(filename):
        if not os.path.exists(os.path.dirname(filename)):
            try:
                os.makedirs(os.path.dirname(filename))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        if not os.path.isfile(filename):
            open(filename, "w").close()

    def setup(self):

        # Setting up Postgresql
        # params = {
        #   'database': self.psql_db_database,
        #   'user': self.psql_db_user,
        #   'password': self.psql_db_pass,
        #   'host': self.psql_db_host,
        #   'port': self.psql_db_port
        #}
        #self.conn = psycopg2.connect(**params)
        #self.ps_cur = self.conn.cursor()
        #self.ps_cur.execute(
        #    "prepare insert_packet as "
        #    "INSERT INTO ppp_packets (created, data) values($1, $2)")
        self.lock.acquire()
        if self.clear_db_on_startup:
            self.ps_cur.execute("TRUNCATE TABLE ppp_packets RESTART IDENTITY;TRUNCATE TABLE ppp_flows RESTART IDENTITY;")
        self.conn.commit()
        self.lock.release()
		
        call(["rm", self.eth0_global_pcap_path])  # clear global pcap files

        self.safe_create_file(self.eth0_aux_pcap_path)
        self.safe_create_file(self.eth0_temp_pcap_path)

        # Set the handle to publish events
        self._publish = self._communicator.publish

    def process_pcap_file(self, path, packets, profiling=False):
        t0 = time.time()  # Used for profilling
        f = open(path, "rb")
        cap = dpkt.pcap.Reader(f)
        # Extract pcap file metadata
        cap_length, cap_end_time = self.get_cap_metadata(path)
        t1 = time.time()  # Used for profilling
        # Sync with previous read attempt
        #start_index = self.pcap_sync_time(packets_list, cap, cap_length)
        start_index = 0
        t2 = time.time()  # Used for profilling

        # Add new packets to the global pcap file
        self.update_global_pcap(path, cap_length, start_index)

        if start_index == -1:
            logging.info("We lost some packets")
            start_index = 0
        # print('Starting processing of pcap file from index : ', start_index)
        l = self.read_pcap_dpkt(cap, cap_length, start_index)
        t3 = time.time()
        # print("New records read from pcap file : ", len(l))
        packets = packets + len(l)
        t4 = time.time()

        # Extract flows from the updated pcap file
        cur_flows = self.extract_flows()
        # Store old flows to the db and calc the start time
        #earliest_alive_flow_ts = self.trim_flows_2(cur_flows, cap_end_time)
        earliest_alive_flow_ts = self.trim_flows_in_mem(cur_flows, cap_end_time)
        # Remove packets older than all alive flows from the pcap file
        self.trim_pcap_file(earliest_alive_flow_ts)
        del cap

        f.close()

        if profiling:
            logging.info("Read from disk : {:.5f}".format(t1 - t0))
            logging.info("Sync with previous pcap : {:.5f}".format(t2 - t1))
            logging.info("Extract packets : {:.5f}".format(t3 - t2))
            logging.info("Append to list : {:.5f}".format(t4 - t3))
            logging.info("\n")

    def get_cap_metadata(self, cap_path):
        text = check_output(["capinfos", "-c", "-M", '-e', '-S',
                             cap_path]).decode('utf-8')
        text = text.split('\n')
        cap_length = int(text[1].split()[-1])
        if cap_length > 0:
            cap_end_time = float(text[2].split()[-1].replace(',', '.'))
        else:
            cap_end_time = -1
        return cap_length, cap_end_time

    def pcap_sync_time(self, packets_list, cap, cap_length):
        start_index = -1
        # if global list of packets read is empty then this is probably the first pcap file. So start from the first packet
        if len(packets_list) == 0:
            start_index = 0
        else:  # else this is not the first pcap file... index at which unread packets start should be detected


            pivot_time = packets_list[-1]['time'] # Use the last packet of the previous run to find its  position in the pcap and do binary search, with regards to timestamps (they are sorted)
            pers = 0
            while packets_list[-pers-2]['time'] == pivot_time:
                pers = pers + 1

            # print("Syncing : pivot time = {} and pers = {}".format(pivot_time,pers))

            cap_times = list(map(lambda x: float(x.frame_info.time_epoch), cap))
            if pivot_time in cap_times:
                start_index = cap_times.index(pivot_time) + pers
                start_index = start_index + 1
            else:
                #print("no sync...")
                start_index = 0
            # print("Sync_index = {}".format(start_index))

        return start_index

    def update_global_pcap(self, cap_path, cap_length, start_index):

        #  Keep only new packets for the newly read pcap file
        call(["editcap", "-r", "-F", "pcap", cap_path, self.eth0_temp_pcap_path, str(start_index+1)+"-"+str(cap_length)])

        # Extract their payloads to a temp txt file

        global payloads

        if self.ip_packets_payload_analysis:
            payloads_text = str(check_output(["python", "test_scapy.py", self.eth0_temp_pcap_path]))
            payloads = payloads_text.split("*************************")
            payloads.pop(-1) #  remove the last empty record of the list
            #print("Extracted {} payloads".format(len(payloads)))

            edited_payloads = []
            for tp in payloads:
                final_payload = self.extract_payload_ascii(tp)
                edited_payloads.append(final_payload)

            payloads = edited_payloads[:]
        else:
            payloads = cap_length*["-"]

        if os.path.isfile(self.eth0_global_pcap_path):
            # concatenate global and temp pcap files
            call(['mergecap', '-a', '-F', 'pcap', '-w', self.eth0_aux_pcap_path, self.eth0_global_pcap_path, self.eth0_temp_pcap_path])
            call(['mv', self.eth0_aux_pcap_path, self.eth0_global_pcap_path])
        else:
            # create a new global file by copying temp pcap file
            call(["cp", self.eth0_temp_pcap_path, self.eth0_global_pcap_path])

    def extract_payload_ascii(self, tp):
        tpl = tp.split("\\n")
        if len(tpl) == 1:
            tpl = tpl[0].split("\n")
        final_payload = ""
        for t in tpl:
            if t != "":
                final_payload = final_payload + t[-16:]
        return final_payload

    def extract_flows(self):
        all_flows = []
        #  standard labels of the format of data output of libprotoident
        lpi_labels = ['prot', 'ip_a', 'ip_b', 'port_a', 'port_b', 'tran_prot', 'ts_start', 'ts_end', 'tb_a', 'tb_b',
                      'f4b_a', '-', 'sfp_a', 'f4b_b', "-", 'sfp_b', ]

        #  feed global pcap file to libprotoident
        flows_data_text = check_output(["lpi_protoident", self.eth0_global_pcap_path]).decode('utf-8')

        #  for each flow detected create a dictionary with the required info
        for f in flows_data_text.split('\n'):
            flow_data = f.split()
            if len(flow_data) == 16:
                flow = {}
                for i, p in enumerate(lpi_labels):
                    if p != '-':
                        flow[p] = flow_data[i]
                flow['ts_start'] = float(flow['ts_start'])
                flow['ts_end'] = float(flow['ts_end'])
                try:
                    # Read MAC for dictionary
                    flow['mac_a'] = self.macs_dict[flow['ip_a']]
                except:
                    flow['mac_a'] = ''
                try:
                    # Read MAC for dictionary
                    flow['mac_b'] = self.macs_dict[flow['ip_b']]
                except:
                    flow['mac_b'] = ''
                all_flows.append(flow)
        #  return a list of dicts for all flows

        arff_labels = [
            '-', '-', 'packets_a', 'bytes_a', 'packets_b', 'bytes_b',
            'min_load_a', 'mean_load_a', 'max_load_a', 'stdv_load_a',
            'min_load_b', 'mean_load_b', 'max_load_b', 'stdv_load_b',
            'min_iat_a', 'mean_iat_a', 'max_iat_a', 'stdv_iat_a', 'min_iat_b',
            'mean_iat_b', 'max_iat_b', 'stdv_iat_b']

        flows_stats_text = check_output(
            ["lpi_arff", self.eth0_global_pcap_path]).decode('utf-8')

        # lpi_arff returns the default arff format

        flows_stats_text = flows_stats_text.split('@data')

        #  extract values, discards labels

        flows_stats_values = flows_stats_text[1]
        flows_stats_values_list = flows_stats_values.split('\n')
        flows_arff_data = []  # It will hold all arff data produced
        for f in flows_stats_values_list:
            flow_data = f.split(',')
            if len(flow_data) == 24:
                flow = {}
                for i, p in enumerate(arff_labels):
                    if p != '-':
                        flow[p] = flow_data[i]

                flows_arff_data.append(flow)

        for i, f in enumerate(all_flows):
            f.update(flows_arff_data[i])

        return all_flows

    def trim_flows_2(self, cur_flows, cap_end_time):
        if self.storage_db == "psql":
            self.lock.acquire()
            self.ps_cur.execute("SELECT * FROM ppp_flows WHERE data->>'status'='alive';")
            old_flows = self.ps_cur.fetchall()
            self.lock.release()
            max_ts_end = 0
            for cf in cur_flows:
                # update max ts found in cur_flows
                if cf['ts_end'] > max_ts_end:
                    max_ts_end = cf['ts_end']
                found = False
                for of in old_flows:
                    if cf['ip_a'] == of[1]['ip_a'] and cf['ip_b'] == of[1]['ip_b'] and cf['port_a'] == of[1]['port_a'] and cf['port_b'] == of[1]['port_b']:
                        # print("flow found")
                        found = True
                        if cf['packets_a']+cf['packets_b'] > of[1]['packets_a'] + of[1]['packets_b']:
                            # print("flow updated")
                            cf['status'] = 'alive'
                            self.lock.acquire()
                            self.ps_cur.execute("UPDATE ppp_flows SET data={} WHERE id = {};".format(Json(cf), of[0]))
                            self.conn.commit()
                            self.lock.release()
                        break
                if not found:
                    cf['status'] = 'alive'
                    self.lock.acquire()
                    self.ps_cur.execute("INSERT INTO ppp_flows (created, data) values(?, ?);", (datetime.utcnow(), Json(cf)))
                    self.conn.commit()
                    self.lock.release()
                    # print("flow added")

            for of in old_flows:
                if of[1]['ts_end'] < max_ts_end - self.kill_flow_waitime:
                    of[1]['status'] = 'expired'
                    self.lock.acquire()
                    self.ps_cur.execute("UPDATE ppp_flows SET data={} WHERE id = {};".format(Json(of[1]), of[0]))
                    self.conn.commit()
                    self.lock.release()
                    #added for sending zmq message for each flow
                    ###############################################
                    if_id = InterfaceId()
                    if_id.value = self._interface.id.value
                    self.publish_new_flow(if_id, of[0], of[1]['ip_a'], of[1]['ip_b'], int(of[1]['tb_a']), int(of[1]['packets_a']), int(of[1]['tb_b']), int(of[1]['packets_b']))
                    ################################################
        return datetime.fromtimestamp(max_ts_end)

    def trim_flows_in_mem(self, cur_flows, cap_end_time):

        max_ts_end = 0
        min_ts_start = 10000000000 #infinity
        flows_buffer = []
        ## For each one of the new flows search if it is the same with one of the active ones
        ## If yes update the specific active flow
        ## Otherwise append the new flow to the buffer
        for cf in cur_flows:
            # update max ts found in cur_flows
            if cf['ts_end'] > max_ts_end:
                max_ts_end = cf['ts_end']
            if cf['ts_start'] < min_ts_start:
                min_ts_start = cf['ts_start']
            found = False
            for i, of in enumerate(self.active_flows):
                if cf['ip_a'] == of['ip_a'] and cf['ip_b'] == of['ip_b'] and cf['port_a'] == of['port_a'] and \
                        cf['port_b'] == of['port_b'] and cf['ts_start'] < of['ts_end'] + self.kill_flow_waitime:
                    found = True

                    if cf['packets_a'] + cf['packets_b'] > of['packets_a'] + of['packets_b']:
                        cf['status'] = 'alive'
                        self.active_flows[i] = cf
                    break
            if not found:
                cf['status'] = 'alive'
                flows_buffer.append(cf)
                # print("flow added")
        active_flows_expired = []
        for i, of in enumerate(self.active_flows):
            if of['ts_end'] < max_ts_end - self.kill_flow_waitime:
                of['status'] = 'expired'
                active_flows_expired.append(i)
                self.lock.acquire()
                self.ps_cur.execute("INSERT INTO ppp_flows (created, data) values(now(), {}) RETURNING id;".format(Json(of)))
                new_id = self.ps_cur.fetchone()[0]
                self.conn.commit()
                self.lock.release()
                # added for sending zmq message for each flow
                ###############################################
                if_id = InterfaceId()
                if_id.value = self._interface.id.value
                self.publish_new_flow(if_id, new_id, of['ip_a'], of['ip_b'], int(of['tb_a']), int(of['packets_a']), int(of['tb_b']), int(of['packets_b']))
                ################################################
        ## Remove expired flows from active_flows
        for i in reversed(active_flows_expired):
            del self.active_flows[i]
        ## Add new active_flows
        self.active_flows.extend(flows_buffer)

        return datetime.fromtimestamp(max_ts_end)

    def flush_flows(self, cur_flows):
        #  Store all flows to the db. This function is called at the end of a simulation
        self.lock.acquire()
        for f in cur_flows:
                if self.storage_db == "psql":
                        self.ps_cur.execute("INSERT INTO ppp_flows (created, data) values(now(), {});" .format( Json(f)))
                        self.conn.commit()
        self.lock.release()

    def trim_pcap_file(self, earliest_alive_flow_ts):
        # Use the start time of the earliest flow to detect packets older than that
        # Remove these packets from the global pcap file
        if earliest_alive_flow_ts is None: # No alive flows left
            earliest_alive_flow_ts = datetime.now() # remove all packets

        call(["editcap", "-F", "pcap", '-A', earliest_alive_flow_ts.strftime("%Y-%m-%d %H:%M:%S"), self.eth0_global_pcap_path, self.eth0_aux_pcap_path])
        call(['mv', self.eth0_aux_pcap_path, self.eth0_global_pcap_path])

    def read_pcap_dpkt(self, cap, cap_length, start_index=0):
        partial_packets_list = []
        global payloads
        existing_packets = self.packets
        i = 0
        sql = ''

        for ts, buf in cap:

            try:
                if i and i % 300 == 0:
                    logging.debug("Progress {}/{} ...".format(
                        str(i), str(cap_length)))
                    if not self.ps_cur.closed:
                        self.lock.acquire()
                        self.ps_cur.execute(sql)
                        self.conn.commit()
                        self.lock.release()
                    sql = ''

                pd = self.packet_check_dpkt(buf, ts)  #, previous_hash)
                # pd['payload'] = payloads[i - start_index]
                # pd['id'] = existing_packets + i - start_index
                if pd and self.storage_db == "psql":
                    sql = sql + "INSERT INTO ppp_packets (created, data) values(now(), {});".format(Json(pd))

                partial_packets_list.append(pd)
                i = i + 1
            except Exception as ex:
                logging.exception("Unexpected error at packet")
                break

        if sql and not self.ps_cur.closed:
            self.lock.acquire()
            self.ps_cur.execute(sql)
            self.conn.commit()
            self.lock.release()

        return partial_packets_list

    def packet_check_dpkt(self, packet, ts):
        packet_details = {}
        p = dpkt.ppp.PPP(packet)
        if not isinstance(p, dpkt.ppp.PPP):
            #print "It is NOT instance", packet
            return
            
        hex = dpkt.dpkt.hexdump(packet,length=1) #extract the hex format of the packet
        lines = hex.splitlines()
        try:
            ip_src = '.'.join(str(k) for k in [int(j,16) for j in [i.split()[1] for i in lines[28:32]]]) #source IP address
            ip_dst = '.'.join(str(k) for k in [int(j,16) for j in [i.split()[1] for i in lines[32:36]]]) #destination IP address

            descr = ''
            current_time = time.time()
            if (ip_src not in  self.device_dict):
                if self.is_internal (ip_src):
					descr = 'internal'
					if_id = InterfaceId()
					if_id.value = self._interface.id.value	
					if  (current_time-self.start_time)> self.silence_alert: #if the silence alert period exceed the current time
						self.publish_new_device(if_id, ip_src, current_time)
                else: 
					descr = 'external'
					if  (current_time-self.start_time)> self.silence_alert: #if the silence alert period exceed the current time
						self.publish_external_IP(ip_src, current_time)
                self.device_dict [ip_src] = descr
            if (ip_dst not in self.device_dict) :
                if self.is_internal (ip_dst):
					descr = 'internal'
					if_id = InterfaceId()
					if_id.value = self._interface.id.value	
					if  (current_time-self.start_time)> self.silence_alert: #if the silence alert period exceed the current time
						self.publish_new_device(if_id, ip_dst, current_time)
                else:
					descr = 'external'
					if  (current_time-self.start_time)> self.silence_alert: #if the silence alert period exceed the current time
						self.publish_external_IP(ip_dst, current_time)
                self.device_dict[ip_dst] = descr
            #print (self.device_dict)
            #   self.macs_dict[ip_src] = eth_src
            #if ip_dst not in self.macs_dict:
            #   self.macs_dict[ip_dst] = eth_dst
            #packet_details['src_mac'] = eth_src
            #packet_details['dst_mac'] = eth_dst
            packet_details['src_ip'] = ip_src
            packet_details['dst_ip'] = ip_dst
            packet_details['time'] = float(ts)
            packet_details['length'] = len (packet)
            packet_details['transport'] =  int([i.split()[1] for i in lines[25:26]][0], 16) #transport layer
            if packet_details['transport'] == 6 or packet_details['transport'] == 17: #in the case transport layer is TCP or UDP #ICMP protocol does not have ports
				sport = [int(j,16) for j in[i.split()[1] for i in lines[36:38]]]  #source port
				packet_details['sport'] = sport[0]*16**2+sport[1]
				dport = [int(j,16) for j in[i.split()[1] for i in lines[38:40]]]  #destination port
				packet_details['dport'] = dport[0]*16**2+dport[1]
	
            packet_details['data'] = repr(p.data)
    
            return packet_details
        except:
            logging.exception("Failed to create IP - MAC dict.")

    def publish_proc_alert(self, alert_type, if_id, file_name):
        '''
        Publishes an alert message to GHOST's modules on the progress of
        processing the PCAP files.
        '''
        # Build the Alert message
        alert = FileProcessing()
        alert.alert_type = alert_type
        alert.if_id.value = if_id.value
        alert.file_name = file_name

        # Publish it
        self._publish(self.NDFA_ALERT_TOPIC, alert.SerializeToString())
        logging.debug("Alert was published [" + self.NDFA_ALERT_TOPIC + "," +
                      self.NDFA_PUBSUB_ADDRESS + "]")

    def publish_new_flow(self, if_id, flow_id, src_address, dst_address, total_bytes_a, packets_a, total_bytes_b, packets_b):
        '''
        Publishes an alert message to GHOST's modules on the progress of
        capturing new flow.
        '''
        # Build the Alert message
        fl = FlowAdded()
        fl.if_id.value = if_id.value
        fl.flow_id = flow_id
        fl.src_address = src_address
        fl.dst_address = dst_address
        fl.total_bytes_a = total_bytes_a
        fl.packets_a = packets_a
        fl.total_bytes_b = total_bytes_b
        fl.packets_b = packets_b
        fl.type = 5 #  InterfaceType:     PPP = 5;
        # Publish it
        self._publish(self.NDFA_FLOW_TOPIC, fl.SerializeToString())
        logging.debug("Flow was published [" + self.NDFA_FLOW_TOPIC + "," +
                     self.NDFA_PUBSUB_ADDRESS + "]")
					 
					 
    def publish_external_IP(self, ip_addr, event_time):
        '''
        Publishes an alert message to GHOST's modules on the 
        detecting a new external IP
        
        Parameters:
            ip_addr -  the new external IP
            event_imestamp - the timestamp that the event is detected
        '''
        # Build the Alert message
        alert = NewExternalIp ()
        alert.ip_address  = ip_addr
        alert.event_timestamp = event_time
        
        # Publish it
        self._publish(self.NDFA_EXTERNAL_IP_TOPIC, alert.SerializeToString())
        logging.debug("New External IP detected "+ip_addr+" at "+str(event_time)+" [" + self.NDFA_EXTERNAL_IP_TOPIC + "," +
                      self.NDFA_PUBSUB_ADDRESS + "]")
					  
    def publish_new_device(self, if_id, addr, event_time):
        '''
        Publishes an alert message to GHOST's modules on the 
        detecting of new device
        
        Parameters:
             InterfaceId -- ID of the interface 
			 address -- string of the address
			 InterfaceType -- type of the interface (IPv4)
			 event_imestamp - the timestamp that the event is detected
        '''
        # Build the Alert message
        alert = NewDevice ()
        alert.if_id.value  = if_id.value
        alert.address  = addr
        alert.type = 0 #  InterfaceType:   IP4 = 0;
		
        # Publish it
        self._publish(self.NDFA_NEWDEVICE_TOPIC, alert.SerializeToString())
        logging.debug("New device detected with addresses "+addr+" at "+str(event_time)+" [" + self.NDFA_NEWDEVICE_TOPIC + "," +
                      self.NDFA_PUBSUB_ADDRESS + "]")
					  
    """
    Auxiliary functions for IPTracker
    """

    def get_ip_address(self,ifname):  #returns the local IP of the GW
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
            )[20:24])
			
    def get_MAC_address(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
        return ':'.join(['%02x' % ord(char) for char in info[18:24]])
		
    def is_internal (self, otherIP):
			for inter in self.internal_IP_range:
				prefix_address, net_size = inter.split("/")
				net_size = int(net_size)
				prefix_network = self.network_prefix(prefix_address, net_size)
				otherIP_prefix = self.network_prefix(otherIP, net_size)
				if prefix_network == otherIP_prefix:
						return True
			return False

    def network_prefix (self, ip, net_size):
		ip_bin = ('').join([format(int(i), '08b') for i in ip.split(".")]) #IP address in binary form
		return ip_bin[0:32-(32-net_size)]     # network prefix in binary
     
    

    def run(self, loop):
        self.setup()

        # self.packets_list = [] # List to store packets
        self.packets = 0
        self.device_dict = {} # set of all devices
        
        self.device_dict [self.get_ip_address('eth0') ]=  'GW'  # public IP interface of GW TVES
        self.device_dict [self.get_ip_address('wlan0') ] = 'GW' # wireless IP interface of GW TVES
        self.device_dict [self.get_ip_address('ppp0')  ]= 'GW' # PPP interface of GW TVES
        #internal IP ranges
        self.internal_IP_range = [self.get_ip_address('wlan0')+'/24', self.get_ip_address('ppp0')+'/24']   #Internal Range of  IPs

        #self.device_dict[self.get_ip_address('ens33')] = 'GW'   # public IP interface of GW
        #self.internal_IP_range = ['192.168.1.1'+'/24'] #Internal Range of  IPs             
        #fetch the ip address of from device_info Table
        self.lock.acquire()
        self.ps_cur.execute("SELECT ip4_device from device_info where interface_type = '5';")
        ip_addresses = self.ps_cur.fetchall()
        self.lock.release()
        for ip_addr in ip_addresses:
                self.device_dict [socket.inet_ntoa(struct.pack(">L", ip_addr[0]))] = 'internal' 
		#print (self.device_dict)

        if self.pcap_path_eth0[-5:] == ".pcap":  # file_mode
            # process_pcap_file(pcap_path_eth0, packets_list, profiling=True)
            if loop:
                while self.keep_running:
                    # copyfile("pcap_files/test10.pcap",
                    #          "pcap_files/read.pcap")
                    # os.remove('pcap_files/test10.pcap')
                    self.process_pcap_file(
                        self.pcap_path_eth0, self.packets, profiling=False)
            else:
                self.process_pcap_file(self.pcap_path_eth0, self.packets,
                                       profiling=False)
            # store remaining alive flows to db
            remaining_flows = self.extract_flows()
            self.flush_flows(remaining_flows)
            # print(self.packets)
        else:  # directory_mode
            import glob
            pcap_files = []
            if loop:
                while self.keep_running:
                    new_pcap_files = []
                    common_files = 0
                    new_files = 0
                    for filename in glob.iglob(self.pcap_path_eth0+"/*"):
                        if filename in pcap_files:
                            common_files = common_files + 1
                            # print("common files: ", common_files, filename)
                            continue
                        else:
                            new_files = new_files + 1
                            # print("new files: ", new_files, filename)
                            new_pcap_files.append(filename)
                            pcap_files.append(filename)
                    logging.debug("Number of existing pcap files that have been read: {}".format(common_files))
                    logging.debug("Number of new pcap files: {}".format(new_files-1))
                    new_pcap_files = sorted(new_pcap_files, key=lambda x: x.rsplit('_')[-1])#new_pcap_files.sort()
                    pcap_files = sorted(pcap_files, key=lambda x: x.rsplit('_')[-1])#pcap_files.sort()
                    # print(pcap_files)
                    # print(new_pcap_files)
                    # if common_files == 0:
                    #     print("packets may have been lost")
                    if new_files == 0:
                        logging.debug("No new pcap files to read yet")
                        time.sleep(1)
                        continue
                    elif new_files == 1:
                        logging.debug("No new pcap files to read yet")
                        # the last pcap file has not yet been completed,
                        # thus will be read in next iteration
                        del new_pcap_files[-1]
                        del pcap_files[-1]
                        time.sleep(1)
                        continue
                    else:
                        # the last pcap file has not yet been completed,
                        # thus will be read in next iteration
                        del new_pcap_files[-1]
                        del pcap_files[-1]
                    pcap_len = len(pcap_files)
                    if pcap_len > 2 * self.NUM_OF_PCAP_FILES:
                        for k in range(0, self.NUM_OF_PCAP_FILES):
                            del pcap_files[0]
                    for f in sorted(new_pcap_files, key=lambda x: x.rsplit('_')[-1]): #sorted(new_pcap_files):
                        if not self.keep_running:
                            break

                        logging.info("Reading file: {} ...".format(f))
                        # Publish the start of processing the file
                        if_id = InterfaceId()
                        if_id.value = self._interface.id.value
                        self.publish_proc_alert(FileProcessing.BEGIN, if_id, f)
                        try:
                            self.process_pcap_file(f, self.packets,
                                                   profiling=False)
                        except Exception as ex:
                            logging.exception("Failed to process pcap file:")
                        logging.info("File: {} processed".format(f))
            else:
                pcap_files = []
                for filename in glob.iglob(self.pcap_path_eth0 + "/*"):
                    pcap_files.append(filename)
                for f in sorted(pcap_files, key=lambda x: x.rsplit('_')[-1]): #sorted(pcap_files):
                    self.process_pcap_file(f, self.packets, profiling=False)

            try:
                # store remaining alive flows to db
                remaining_flows = self.extract_flows()
                self.flush_flows(remaining_flows)
            except Exception as ex:
                print(traceback.format_exc())
                logging.error("Failed to extract/flush flows: %s", str(ex))

    def close(self):
        logging.info("Stopping")
        self.keep_running = False
        #self.conn.close()
        logging.info("Stopped")
