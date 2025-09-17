from subprocess import check_output
import time
import logging
import os
import errno
import json

import pyshark
import timeout_decorator
import psycopg2
from psycopg2.extras import Json

from ghost_ndfa import (NDFA_PUBSUB_ADDRESS, NDFA_ALERT_TOPIC, NDFA_FLOW_TOPIC,NDFA_NEWDEVICE_TOPIC)

from ghost_protocol.ndfa_pb2 import FileProcessing
from ghost_protocol.inter_pb2 import InterfaceId
from ghost_protocol.ndfa_pb2 import FlowAdded
from ghost_protocol.ndfa_pb2 import NewDevice


class ZwPacketsProcessor:

    def __init__(self, config, communicator, interface, conn, ps_cur, lock):
        self.keep_running = True

        self.storage_db = config.get('Storage', 'storage_db')

        self.clear_db_on_startup = config.getboolean(
            'Options', 'clear_db_on_startup')
        self.ip_packets_payload_analysis = config.getboolean(
            'Options', 'ip_packets_payload_analysis')

        self.pcap_path_zw = interface.config.pcap_path
        self.root_path = config.get('Paths', 'root_path')

        #self.bt_temp_pcap_path = os.path.join(
        #    self.root_path, "temp_" + interface.description + ".pcap")
        #self.bt_global_ip_pcap_path = os.path.join(
        #    self.root_path, "global_" + interface.description + ".pcap")
        #self.bt_aux_pcap_path = os.path.join(
        #    self.root_path, "aux_" + interface.description + ".pcap")

        self.NDFA_PUBSUB_ADDRESS = NDFA_PUBSUB_ADDRESS
        self.NDFA_ALERT_TOPIC = NDFA_ALERT_TOPIC
        self.NDFA_FLOW_TOPIC = NDFA_FLOW_TOPIC
        self.NDFA_NEWDEVICE_TOPIC = NDFA_NEWDEVICE_TOPIC

        self.psql_db_host = config.get('PostgreSQL', 'host')
        self.psql_db_user = config.get('PostgreSQL', 'user')
        self.psql_db_pass = config.get('PostgreSQL', 'pass')
        self.psql_db_database = config.get('PostgreSQL', 'database')
        self.psql_db_port = config.get('PostgreSQL', 'port')

        self.NUM_OF_PCAP_FILES = int(config.get('Files', 'NUM_OF_PCAP_FILES'))
        #self.kill_flow_waitime = float(config.get('Time', 'kill_flow_waitime'))
        self.zw_batches_kill_time = float(
            config.get('Time', 'zw_batches_kill_time'))
			
        self.silence_alert = float(config.get('Time', 'silence_alert') )
        self.start_time  = time.time()

        self._communicator = communicator
        self._interface = interface

        self.conn = conn
        self.ps_cur = ps_cur
        self.lock = lock

    def execute_on_db(self, query, get_results = False):
        #self.conn = psycopg2.connect(**self.params)
        self.lock.acquire()
        #self.ps_cur = self.conn.cursor()
        self.ps_cur.execute(query)
        if get_results :
                res = self.ps_cur.fetchone()[0]
        self.conn.commit()
        self.lock.release()
        #self.conn.close()
        if get_results:
                return res

    def safe_create_file(self,filename):
        if not os.path.exists(os.path.dirname(filename)):
            try:
                os.makedirs(os.path.dirname(filename))
            except OSError as exc: # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        if not os.path.isfile(filename):
            open(filename, "w").close()

    def setup(self):
        # Setting up Postgresql
        #self.params = {
        #   'database': self.psql_db_database,
        #  'user': self.psql_db_user,
        # 'password': self.psql_db_pass,
        # 'host': self.psql_db_host,
        # 'port': self.psql_db_port}

        #self.conn = psycopg2.connect(**self.params)

        if self.clear_db_on_startup:
            self.execute_on_db("TRUNCATE TABLE zw_packets RESTART IDENTITY;TRUNCATE TABLE zw_batches RESTART IDENTITY;")

        # self.safe_create_file(self.bt_aux_pcap_path)
        # self.safe_create_file(self.bt_temp_pcap_path)
        # self.safe_create_file(self.bt_global_ip_pcap_path)

        self.packets_list = []
        self.running_batch = {}
        
        # Set the handle to publish events
        self._publish = self._communicator.publish


    #@timeout_decorator.timeout(5, timeout_exception=StopIteration, use_signals=False)
    def process_pcap_file(self, path, profiling=False):
		script = os.path.dirname(os.path.realpath(__file__)) + "/pcap_zw_process.py"
		try:
				a = check_output(["python", script, path]) # e.g, "python pcap_zw_process.py XXX.pcap"
				packets = json.loads(a)
				current_time = time.time()
				for pd in packets:		
						# added for sending zmq message for each new device
						###############################################
						if pd['dst_zw_addr'] not in self.device_set:
						    self.device_set.add(pd['dst_zw_addr'])
						    if_id = InterfaceId()
						    if_id.value = self._interface.id.value
						    if  (current_time-self.start_time)> self.silence_alert: #if the silence alert period exceed the current time
								self.publish_new_device(if_id, pd['dst_zw_addr'], current_time)
						if pd['src_zw_addr'] not in self.device_set:
						    self.device_set.add(pd['src_zw_addr'])
						    if_id = InterfaceId()
						    if_id.value = self._interface.id.value
						    if  (current_time-self.start_time)> self.silence_alert: #if the silence alert period exceed the current time
								self.publish_new_device(if_id, pd['src_zw_addr'], current_time)
						################################################
						self.update_batches(pd)
						self.execute_on_db(
                    "INSERT INTO zw_packets (created, data) values(now(), {});".format(Json(pd)))
		except :
				logging.error("Failed to process ZW pcap file : {}".format(path))
		
    def get_batches_key(self,p):
        if p['src_zw_addr']<p['dst_zw_addr']:
            return p['src_zw_addr']+p['dst_zw_addr']
        else:
            return p['dst_zw_addr']+ p['src_zw_addr']

    def update_batches(self, p):
        key = self.get_batches_key(p)
        if key not in self.running_batch.keys() : # No existing batch -> start a new one
            self.running_batch[key] = [p]
        elif p["time"] - self.running_batch[key][-1]["time"] < self.zw_batches_kill_time:
            self.running_batch[key].append(p)
        else:
            self.kill_batch(key)
            self.running_batch[key] = [p]

        ## We have to manually check all running batches, in order to kill expired ones
        for key in self.running_batch.keys():
            if self.running_batch[key][-1]['time']< p['time'] - self.zw_batches_kill_time:
                self.kill_batch(key)
                del self.running_batch[key]

    def kill_batch(self,key):
        batch_details = {}

        batch_details["start_time"] = self.running_batch[key][0]["time"]
        batch_details["stop_time"] = self.running_batch[key][-1]["time"]
        batch_details["duration"] = batch_details["stop_time"] - batch_details["start_time"]
        batch_details["number_of_packets"] = len(self.running_batch[key])
        batch_details["src_zw_addr"] = self.running_batch[key][0]["src_zw_addr"]
        batch_details["dst_zw_addr"] = self.running_batch[key][0]["dst_zw_addr"]
        min_size = self.running_batch[key][0]["length"]
        max_size = self.running_batch[key][0]["length"]
        sum_size = 0
        total_bytes_a = 0
        total_bytes_b = 0
        packets_a = 0
        packets_b = 0

        for p in self.running_batch[key]:
            if p["length"] > max_size:
                max_size = p["length"]
            if p["length"] < min_size:
                min_size = p["length"]

            if p["src_zw_addr"]  == batch_details["src_zw_addr"]: # if the sender is A
                total_bytes_a = total_bytes_a +  p["length"] 
                packets_a = packets_a + 1
            elif p["src_zw_addr"]  == batch_details["dst_zw_addr"] : # if the sender is B
                total_bytes_b = total_bytes_b +  p["length"] 
                packets_b = packets_b + 1      
            sum_size = sum_size + p["length"]				
        average_size = sum_size / float(batch_details["number_of_packets"])


        batch_details["min_size"] = min_size
        batch_details["max_size"] = max_size
        batch_details["average_size"] = average_size
        batch_details["total_bytes_a"] = total_bytes_a
        batch_details["total_bytes_b"] = total_bytes_b
        batch_details["packets_a"] = packets_a
        batch_details["packets_b"] = packets_b
        batch_details["sum_size"] = sum_size

        batch_id = self.execute_on_db("INSERT INTO zw_batches (created, data) values(now(), {}) RETURNING id;".format(Json(batch_details)),get_results=True)
        #print(batch_id)	
        # added for sending zmq message for each flow
        ###############################################
        if_id = InterfaceId()
        if_id.value = self._interface.id.value
        self.publish_new_flow(if_id, batch_id,batch_details["src_zw_addr"] , batch_details["dst_zw_addr"], total_bytes_a, packets_a, total_bytes_b, packets_b)
        ################################################
        
    def run(self, loop):
        self.setup()
		
        self.device_set = set() # set of all devices
        #fetch the zw address of from device_info Table
        self.lock.acquire()
        self.ps_cur.execute("SELECT zwave_device_home_id from device_info where interface_type = '4';")
        zw_addresses = self.ps_cur.fetchall()
        self.lock.release()
        for zw_address in zw_addresses:
                s = '{0:016x}'.format(int(zw_address[0], 16))
                s = s[4:]
                s = ':'.join(s[i:i + 2] for i in range(0, 12, 2))
                s = unicode(s, "utf-8")
                self.device_set.add(s)

        
        if self.pcap_path_zw[-5:] == ".pcap":  # file_mode
            if loop:
                while self.keep_running:
                    self.process_pcap_file(self.pcap_path_zw)
            else:
                self.process_pcap_file(self.pcap_path_zw)
            if len(self.running_batch) > 0:
                self.kill_batch()  # kill last batch
        else:  # directory_mode
            import glob
            pcap_files = []
            if loop:
                while self.keep_running:
                    new_pcap_files = []
                    common_files = 0
                    new_files = 0
                    for filename in glob.iglob(self.pcap_path_zw + "/*.pcap"):
                        if filename in pcap_files:
                            common_files = common_files + 1
                            continue
                        else:
                            new_files = new_files + 1
                            new_pcap_files.append(filename)
                            pcap_files.append(filename)
                    logging.info("Number of existing pcap files that have been read: {}".format(common_files))
                    logging.info("Number of new pcap files: {}".format(new_files-1))
                    new_pcap_files = sorted(new_pcap_files, key=lambda x: x.rsplit('_')[-1])#new_pcap_files.sort()
                    pcap_files = sorted(pcap_files, key=lambda x: x.rsplit('_')[-1])#pcap_files.sort()
                    if new_files == 0:
                        logging.info("No new pcap files to read yet")
                        time.sleep(1)
                        continue
                    elif new_files == 1:
                        logging.info("No new pcap files to read yet")
                        del new_pcap_files[-1]  # the last pcap file has not yet been completed,
                        del pcap_files[-1]  # thus will be read in next iteration
                        time.sleep(1)
                        continue
                    else:
                        del new_pcap_files[-1] #the last pcap file has not yet been completed,
                        del pcap_files[-1] #thus will be read in next iteration
                    pcap_len = len(pcap_files)
                    if pcap_len > 2 * self.NUM_OF_PCAP_FILES:
                        for k in range(0, self.NUM_OF_PCAP_FILES):
                            del pcap_files[0]
                    for f in sorted(new_pcap_files, key=lambda x: x.rsplit('_')[-1]): #sorted(new_pcap_files):
                        # Publish the start of processing the file
                        if not self.keep_running:
                            break
                        logging.info("Reading file: {}".format(f))
                        if_id = InterfaceId()
                        if_id.value = self._interface.id.value
                        self.publish_proc_alert(FileProcessing.BEGIN, if_id, f)
                        try:
                            self.process_pcap_file(f, profiling=False)
                        except StopIteration:
                            logging.debug("time...out")

            else:
                for filename in glob.iglob(self.pcap_path_zw + "/*.pcap"):
                    pcap_files.append(filename)
                pcap_files.sort()
                for f in sorted(pcap_files, key=lambda x: x.rsplit('_')[-1]): #sorted(pcap_files):
                    self.process_pcap_file(f)
            #if len(self.running_batch) > 0:
            #    self.kill_batch()  # kill last batch

    def close(self):
        logging.info("Stopping")
        self.keep_running = False
        #self.conn.close()
        logging.info("Stopped")

    def pcap_sync_time(self, packets_list, cap):
        start_index = -1
        # if global list of packets read is empty then this is probably the first pcap file. So start from the first packet
        if len(packets_list) == 0:
            start_index = 0
        else:  # else this is not the first pcap file... index at which unread packets start should be detected

            pivot_time = packets_list[-1]['time'] # Use the last packet of the previous run to find its  position in the pcap and do binary search, with regards to timestamps (they are sorted)
            pers = 0
            while packets_list[-pers - 2]['time'] == pivot_time:
                pers = pers + 1
            #print("Syncing : pivot time = {} and pers = {}".format(pivot_time,pers))

            cap_times = list(map(lambda x: float(x.frame_info.time_epoch), cap))

            if pivot_time in cap_times:
                start_index = cap_times.index(pivot_time) + pers
                start_index = start_index + 1
            else:
                start_index = 0

        return start_index

    def get_cap_metadata(self, cap_path):
        text = check_output(["capinfos", "-c", "-M", '-e', '-S', cap_path]).decode('utf-8')
        text = text.split('\n')
        cap_length = int(text[1].split()[-1])
        cap_length = int(text[1].split()[-1])
        if cap_length > 0:
            cap_end_time = float(text[2].split()[-1].replace(',', '.'))
        else:
            cap_end_time = -1  #No packets in this pcap file
        return cap_length, cap_end_time
		
		
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
        fl.type = 4 #  InterfaceType:     ZWAVE = 4;
        # Publish it
        self._publish(self.NDFA_FLOW_TOPIC, fl.SerializeToString())
        logging.debug("Flow was published [" + self.NDFA_FLOW_TOPIC + "," +
                     self.NDFA_PUBSUB_ADDRESS + "]")

    def publish_new_device(self, if_id, addr, event_time):
        '''
        Publishes an alert message to GHOST's modules on the 
        detecting of new device
        
        Parameters:
             InterfaceId -- ID of the interface 
			 address -- string of the address
			 InterfaceType -- type of the interface (Bluetooth)
			 event_imestamp - the timestamp that the event is detected
        '''
        # Build the Alert message
        alert = NewDevice ()
        alert.if_id.value  = if_id.value
        alert.address  = addr
        alert.type = 4  #  InterfaceType:   ZWAVE = 4;
        alert.event_timestamp = event_time
		
        # Publish it
        self._publish(self.NDFA_NEWDEVICE_TOPIC, alert.SerializeToString())
        logging.debug("New device detected with addresses "+addr+" at "+str(event_time)+" [" + self.NDFA_NEWDEVICE_TOPIC + "," +
                      self.NDFA_PUBSUB_ADDRESS + "]")
