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

from ghost_ndfa import (NDFA_PUBSUB_ADDRESS, NDFA_ALERT_TOPIC, NDFA_FLOW_TOPIC,NDFA_NEWDEVICE_TOPIC,NDFA_PRIVATEDATA_TOPIC)

from ghost_protocol.ndfa_pb2 import FileProcessing
from ghost_protocol.inter_pb2 import InterfaceId
from ghost_protocol.ndfa_pb2 import FlowAdded
from ghost_protocol.ndfa_pb2 import NewDevice
from ghost_protocol.ndfa_pb2 import PrivateData

import commands

import traceback
	
class BtPacketsProcessor:

    def __init__(self, config, communicator, interface, conn, ps_cur, lock):
        self.keep_running = True

        self.storage_db = config.get('Storage', 'storage_db')

        self.clear_db_on_startup = config.getboolean(
            'Options', 'clear_db_on_startup')
        self.bt_ignore_man_packets = config.getboolean(
            'Options', 'bt_ignore_man_packets')
        #print self.bt_ignore_man_packets
        self.ip_packets_payload_analysis = config.getboolean(
            'Options', 'ip_packets_payload_analysis')

        self.pcap_path_bt = interface.config.pcap_path
        self.root_path = config.get('Paths', 'root_path')

        self.bt_temp_pcap_path = os.path.join(
            self.root_path, "temp_" + interface.description + ".pcap")
        self.bt_global_ip_pcap_path = os.path.join(
            self.root_path, "global_" + interface.description + ".pcap")
        self.bt_aux_pcap_path = os.path.join(
            self.root_path, "aux_" + interface.description + ".pcap")

        self.NDFA_PUBSUB_ADDRESS = NDFA_PUBSUB_ADDRESS
        self.NDFA_ALERT_TOPIC = NDFA_ALERT_TOPIC
        self.NDFA_FLOW_TOPIC = NDFA_FLOW_TOPIC
        self.NDFA_NEWDEVICE_TOPIC = NDFA_NEWDEVICE_TOPIC
        self.NDFA_PRIVATEDATA_TOPIC = NDFA_PRIVATEDATA_TOPIC

        self.psql_db_host = config.get('PostgreSQL', 'host')
        self.psql_db_user = config.get('PostgreSQL', 'user')
        self.psql_db_pass = config.get('PostgreSQL', 'pass')
        self.psql_db_database = config.get('PostgreSQL', 'database')
        self.psql_db_port = config.get('PostgreSQL', 'port')

        self.NUM_OF_PCAP_FILES = int(config.get('Files', 'NUM_OF_PCAP_FILES'))
        self.kill_flow_waitime = float(config.get('Time', 'kill_flow_waitime'))
        self.bt_batches_kill_time = float(
            config.get('Time', 'bt_batches_kill_time'))

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
        # self.params = {
        #    'database': self.psql_db_database,
        #    'user': self.psql_db_user,
        #   'password': self.psql_db_pass,
        #   'host': self.psql_db_host,
        #   'port': self.psql_db_port}

        #self.conn = psycopg2.connect(**self.params)

        if self.clear_db_on_startup:
            self.execute_on_db("TRUNCATE TABLE bt_packets RESTART IDENTITY;TRUNCATE TABLE bt_batches RESTART IDENTITY;")

        self.safe_create_file(self.bt_aux_pcap_path)
        self.safe_create_file(self.bt_temp_pcap_path)
        self.safe_create_file(self.bt_global_ip_pcap_path)

        self.running_batch = []
        self.running_batch_data = {}

        # Set the handle to publish events
        self._publish = self._communicator.publish

    #@timeout_decorator.timeout(5, timeout_exception=StopIteration, use_signals=False)
    def process_pcap_file(self, path, profiling=False):
        script = os.path.dirname(os.path.realpath(__file__)) + "/pcap_bt_process.py"
        try:
            a = check_output(["python", script, path, str(self.bt_ignore_man_packets)]) # e.g, "python pcap_bt_process.py XXX.pcap True/False", the third argument indicates whether ignore mgmt packets
            

            packets = json.loads(a)
            for pd in packets:
				#print self.device_set
				current_time = time.time()
				if pd['bt_type'] == "0x00000002" or  pd['bt_type']  == "2":  # only then we have addresses
								# added for sending zmq message for each new device
								###############################################
								if pd['dst_bd_addr'] not in self.device_set:
									self.device_set.add(pd['dst_bd_addr'])
									if_id = InterfaceId()
									if_id.value = self._interface.id.value
									if  (current_time-self.start_time)> self.silence_alert: #if the silence alert period exceed the current time
										self.publish_new_device(if_id, pd['dst_bd_addr'],  current_time)
								if pd['src_bd_addr'] not in self.device_set:
									self.device_set.add(pd['src_bd_addr'])
									if_id = InterfaceId()
									if_id.value = self._interface.id.value
									if  (current_time-self.start_time)> self.silence_alert: #if the silence alert period exceed the current time
										self.publish_new_device(if_id, pd['src_bd_addr'], current_time)
								################################################
								# added for sending zmq message for private data detection
								###############################################
								if 'btatt.opcode'  in pd and pd["btatt.opcode"]  =='0x0000001d': #  Method: Handle Value Indication
									if 'btatt.service_uuid16' in pd and pd['btatt.service_uuid16'] == '6173':# or p.btatt.service_uuid16 == '0x181d': # Service UUID: Weight Scale 0x181d or 6173
										if_id = InterfaceId()
										if_id.value = self._interface.id.value
										self.publish_private_data(if_id, pd["src_bd_addr"],  'Weight Scale: '+str(pd['btatt.value']), current_time)
									elif 'btatt.service_uuid16' in pd and pd['btatt.service_uuid16'] == '6160':# or p.btatt.service_uuid16 == '0x1810': # Service UUID: Weight Scale 0x1810 or 6160
										if_id = InterfaceId()
										if_id.value = self._interface.id.value
										self.publish_private_data(if_id, pd["src_bd_addr"],  'Blood Pressure Meter: '+str(pd['btatt.value']), current_time)


				self.update_batches(pd)
				self.execute_on_db(
                    "INSERT INTO bt_packets (created, data) values(now(), {});".format(Json(pd)))
        except:
            #traceback.print_exc()
            logging.error("Failed to process BT pcap file : {}".format(path)) # general try/catch block
			
    def get_batches_key(self,p):
        if p['src_bd_addr'] < p['dst_bd_addr']:
            return p['src_bd_addr'] + p['dst_bd_addr']
        else:
            return p['dst_bd_addr'] + p['src_bd_addr']


    def update_batches(self, p):
        if p['taxonomy'] == 'man':
            if len(self.running_batch) == 0: # No existing batch -> start a new one
                self.running_batch = [p]
            elif p["time"] - self.running_batch[-1]["time"] < self.bt_batches_kill_time:
                self.running_batch.append(p)
            else:
                self.kill_batch()
                self.running_batch = [p]
        else:
            key = self.get_batches_key(p)
            if key not in self.running_batch_data.keys(): # No existing batch -> start a new one
                self.running_batch_data[key] = [p]
            elif p["time"] - self.running_batch_data[key][-1]["time"] < self.bt_batches_kill_time:
                self.running_batch_data[key].append(p)
            else:
                self.kill_batch_data(key)
                self.running_batch_data[key] = [p]


    def kill_batch(self):
        batch_details = {}

        batch_details["taxonomy"] = self.running_batch[0]["taxonomy"]
        batch_details["start_time"] = self.running_batch[0]["time"]
        batch_details["stop_time"] = self.running_batch[-1]["time"]
        batch_details["duration"] = batch_details["stop_time"] - batch_details["start_time"]
        batch_details["number_of_packets"] = len(self.running_batch)
        batch_hash = ""
        min_size = self.running_batch[0]["length"]
        max_size = self.running_batch[0]["length"]
        sum_size = 0

        for p in self.running_batch:
            batch_hash = batch_hash + p["bt_type"][-1]
            if p["length"] > max_size:
                max_size = p["length"]
            if p["length"] < min_size:
                min_size = p["length"]
            sum_size = sum_size + p["length"]

        average_size = sum_size / float(batch_details["number_of_packets"])
        batch_details["batch_id"] = batch_hash
        batch_details["min_size"] = min_size
        batch_details["max_size"] = max_size
        batch_details["average_size"] = average_size 

        batch_id = self.execute_on_db("INSERT INTO bt_batches (created, data) values(now(), {}) RETURNING id;".format(Json(batch_details)),get_results=True)
        # added for sending zmq message for each flow
        ###############################################
        if_id = InterfaceId()
        if_id.value = self._interface.id.value
        self.publish_new_flow(if_id, batch_id, "-", "-", sum_size, batch_details["number_of_packets"], -1, -1)
        ################################################
        
        
    def kill_batch_data(self, key):
        batch_details = {}

		

        batch_details["taxonomy"] = self.running_batch_data[key][0]["taxonomy"]
        batch_details["start_time"] = self.running_batch_data[key][0]["time"]
        batch_details["stop_time"] = self.running_batch_data[key][-1]["time"]
        batch_details["duration"] = batch_details["stop_time"] - batch_details["start_time"]
        batch_details["number_of_packets"] = len(self.running_batch_data[key])
        batch_details["src_bd_addr"] = self.running_batch_data[key][0]["src_bd_addr"]
        batch_details["dst_bd_addr"] = self.running_batch_data[key][0]["dst_bd_addr"]
        batch_hash = ""
        min_size = self.running_batch_data[key][0]["length"]
        max_size = self.running_batch_data[key][0]["length"]
        sum_size = 0
        total_bytes_a = 0
        total_bytes_b = 0
        packets_a = 0
        packets_b = 0
        
        for p in self.running_batch_data[key]:
            batch_hash = batch_hash + p["bt_type"][-1]
            if p["length"] > max_size:
                max_size = p["length"]
            if p["length"] < min_size:
                min_size = p["length"]
            if p["src_bd_addr"]  == batch_details["src_bd_addr"]: # if the sender is A
                total_bytes_a = total_bytes_a +  p["length"] 
                packets_a = packets_a + 1
            elif p["src_bd_addr"]  == batch_details["dst_bd_addr"] : # if the sender is B
                total_bytes_b = total_bytes_b +  p["length"] 
                packets_b = packets_b + 1           
            sum_size = sum_size + p["length"]

        average_size = sum_size / float(batch_details["number_of_packets"])
        
			
        batch_details["batch_id"] = batch_hash
        batch_details["min_size"] = min_size
        batch_details["max_size"] = max_size
        batch_details["average_size"] = average_size
        batch_details["total_bytes_a"] = total_bytes_a
        batch_details["total_bytes_b"] = total_bytes_b
        batch_details["packets_a"] = packets_a
        batch_details["packets_b"] = packets_b
        batch_details["sum_size"] = sum_size
		
        batch_id = self.execute_on_db("INSERT INTO bt_batches (created, data) values(now(), {}) RETURNING id;".format(Json(batch_details)),get_results=True)
        # added for sending zmq message for each flow
        ###############################################
        if_id = InterfaceId()
        if_id.value = self._interface.id.value
        self.publish_new_flow(if_id, batch_id,batch_details["src_bd_addr"] , batch_details["dst_bd_addr"], total_bytes_a, packets_a, total_bytes_b, packets_b)
        ################################################
        
    def run(self, loop):
        self.setup()
        
        self.device_set = set() # set of all devices

        #find the BT address of controller 
        self.device_set.add('00:00:00:00:00:00') # default address of GW
        status, output = commands.getstatusoutput("hciconfig")
        self.device_set.add ( output.split("{}:".format("hci0"))[1].split("BD Address: ")[1].split(" ")[0].strip().lower())
        #fetch the bt address of from device_info Table
        self.lock.acquire()
        self.ps_cur.execute("SELECT bluetooth_device from device_info where interface_type = '1';")
        bt_addresses = self.ps_cur.fetchall()
        self.lock.release()
        for bt_address in bt_addresses:
                s = '{0:016x}'.format(bt_address[0])
                s = s[4:]
                s = ':'.join(s[i:i + 2] for i in range(0, 12, 2))      
                self.device_set.add(s)

        
				

        if self.pcap_path_bt[-5:] == ".pcap":  # file_mode
            if loop:
                while self.keep_running:
                    self.process_pcap_file(self.pcap_path_bt)
            else:
                self.process_pcap_file(self.pcap_path_bt)
            if len(self.running_batch) > 0:
                self.kill_batch()  # kill last batch
            if len(self.running_batch_data) > 0:
                self.kill_batch_data()
        else:  # directory_mode
            import glob
            pcap_files = []
            if loop:
                while self.keep_running:
                    new_pcap_files = []
                    common_files = 0
                    new_files = 0
                    for filename in glob.iglob(self.pcap_path_bt + "/*.pcap"):
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
                        if not self.keep_running:
                            break
                        # Publish the start of processing the file
                        logging.info("Reading file: {}".format(f))
                        if_id = InterfaceId()
                        if_id.value = self._interface.id.value
                        self.publish_proc_alert(FileProcessing.BEGIN, if_id, f)
                        try:
                            self.process_pcap_file(f, profiling=False)
                        except StopIteration:
                            logging.debug("time...out")

            else:
                for filename in glob.iglob(self.pcap_path_bt + "/*.pcap"):
                    pcap_files.append(filename)
                pcap_files.sort()
                for f in sorted(pcap_files, key=lambda x: x.rsplit('_')[-1]): #sorted(pcap_files):
                    self.process_pcap_file(f)
            #if len(self.running_batch) > 0:
            #    self.kill_batch()  # kill last batch
            #if len(self.running_batch_data) > 0:
            #    self.kill_batch_data()

    def close(self):
        logging.info("Stopping... received an interruption signal")
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
        fl.type = 1 #  InterfaceType:   BLUETOOTH = 1;
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
        alert.type = 1 #  InterfaceType:   BLUETOOTH = 1;
        alert.event_timestamp = event_time
		
        # Publish it
        self._publish(self.NDFA_NEWDEVICE_TOPIC, alert.SerializeToString())
        logging.debug("New device detected with addresses "+addr+" at "+str(event_time)+" [" + self.NDFA_NEWDEVICE_TOPIC + "," +
                      self.NDFA_PUBSUB_ADDRESS + "]")
					  
    def publish_private_data(self,  if_id, bt_address, private_data, event_time):
        '''
        Publishes an alert message to GHOST's modules on the
        detection of private data.
		
		Parameters:
			bt_address -- the address of the sender
			private_data -- the context of the data
        '''
        # Build the Alert message
        alert = PrivateData()
        alert.if_id.value = if_id.value
        alert.address = bt_address
        alert.type =  1 #  InterfaceType:   BLUETOOTH = 1;
        alert.private_data = private_data
        alert.event_timestamp = event_time


        # Publish it
        self._publish(self.NDFA_PRIVATEDATA_TOPIC, alert.SerializeToString())
        logging.debug("Private data detected from device: "+bt_address+" at "+str(event_time)+" [" + self.NDFA_PRIVATEDATA_TOPIC + "," +
                      self.NDFA_PUBSUB_ADDRESS + "]")

