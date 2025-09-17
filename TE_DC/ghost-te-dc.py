#import the required libraries
import sys, os
import time
import numpy as np
import math
from sklearn.cluster import DBSCAN
import pickle
import schedule
import logging
import logging.handlers
import argparse
import signal
from ghost_te_dc.TEMPLATE_EXTRACTION import TEMPLATE_EXTRACTION
from ghost_te_dc.ENSEMBLE_CLASSIFIER import EC
from ghost_te_dc.DATABASE_COMMUNICATION import DBC
from ghost_te_dc.GET_DEVICES import GD
from ghost_te_dc.ANOMALY_DETECTION import AD
from ghost_te_dc import TE_DC_PUBSUB_ADDRESS
sys.path.append(os.path.relpath(os.path.join('../communication_protocols/python')))
from ghost_protocol.communicator import Communicator
from ghost_protocol.cr_ce_pb2 import ReducedData, CR_CE_Devices, FullData
from ghost_protocol.utils import get_configuration
sys.path.append(os.path.relpath(os.path.join('../CR_CE')))
from ghost_cr_ce import CR_CE_REQUEST_ADDRESS

# TE_DC version number
__version__ = "0.10"

LOG_VALUES = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "notset": logging.NOTSET
}

class TE_DC:

    #initialization of the module
    def __init__(self, config):
        self._communicator = Communicator(None, None, TE_DC_PUBSUB_ADDRESS,[("cr_ce", CR_CE_REQUEST_ADDRESS)] ,[])
        self.loading_phase = False
        self.config = config
        self.training_phase = config.getboolean("Phases", "training_phase")
        self._db_name = config.get("Database", "name")
        self._db_user = config.get("Database", "user")
        self._db_password = config.get("Database", "password")
        self._db_host = config.get("Database", "host")
        self._db_port = config.get("Database", "port")
        self.start = config.get("Time", "start")
        self.interval = config.get("Time", "interval")
        self._log_setup(config)
        self.runner = True
        logging.info("Running...")

    def _log_setup(self, config):
        log_level = LOG_VALUES[config.get("Log", "level")]
        formatter = logging.Formatter(
            '%(asctime)s %(levelno)-1s %(process)-5d %(threadName)-10s] %(message)s')

        # Setup file logger
        file_handler = None
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                config.get("Log", "filename"),
                maxBytes=int(config.get("Log", "maxBytes")),
                backupCount=int(config.get("Log", "backupCount")))
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
        # pylint: disable=W0703
        except Exception:
            pass
        # pylint: enable=W0703

        # Setup syslog logger
        syslog_handler = None
        try:
            if config.getboolean("Log", "syslog"):
                syslog_handler = logging.handlers.SysLogHandler()
                syslog_handler.setLevel(log_level)
                syslog_handler.setFormatter(formatter)
        # pylint: disable=W0703
        except Exception:
            pass
        # pylint: enable=W0703

        # Setup console logger
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)

        logger = logging.getLogger()
        logger.addHandler(console_handler)
        if file_handler:
            logger.addHandler(file_handler)
        if syslog_handler:
            logger.addHandler(syslog_handler)
        logger.setLevel(log_level)
    
    def training(self):
        logging.info("=====================================")
        logging.info("TRAINING PHASE")
        logging.info("=====================================")
        
        #connect to the database
        ps_cur, conn = DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).connect()
        ps_cur.execute("TRUNCATE TABLE te_dc_parameters RESTART IDENTITY;")
        ps_cur.execute("TRUNCATE TABLE templates RESTART IDENTITY;")
        #disconnect from the database
        DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).disconnect(conn)
        
        #get the devices
        ip_devices, bt_devices, zw_devices, rf_devices, zb_devices = GD(self.config).get_devices()
        #connect to the database
        ps_cur, conn = DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).connect()
        #insert to table the training devices in byte format
        ps_cur.execute("INSERT INTO te_dc_parameters VALUES (%s, %s);",("ip", pickle.dumps(ip_devices)))
        ps_cur.execute("INSERT INTO te_dc_parameters VALUES (%s, %s);",("bt", pickle.dumps(bt_devices)))
        ps_cur.execute("INSERT INTO te_dc_parameters VALUES (%s, %s);",("zw", pickle.dumps(zw_devices)))
        ps_cur.execute("INSERT INTO te_dc_parameters VALUES (%s, %s);",("rf", pickle.dumps(rf_devices)))
        ps_cur.execute("INSERT INTO te_dc_parameters VALUES (%s, %s);",("zb", pickle.dumps(zb_devices)))
        conn.commit()
        #disconnect from the database
        DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).disconnect(conn)

        #the current time
        current_time = str(time.time())
        
        
        #call function that requests to CR_CE for training_short
        self._request_CR_CE(TE_DC.data_integrity(ip_devices), TE_DC.data_integrity(bt_devices),
                            TE_DC.data_integrity(zw_devices), TE_DC.data_integrity(rf_devices), TE_DC.data_integrity(zb_devices), "training_short", current_time)

        #call the auxiliary function _clust_class for short duration
        self._clust_class("short")
        
        #call function that requests to CR_CE for training_long 
        self._request_CR_CE(TE_DC.data_integrity(ip_devices), TE_DC.data_integrity(bt_devices),
                            TE_DC.data_integrity(zw_devices), TE_DC.data_integrity(rf_devices), TE_DC.data_integrity(zb_devices), "training_long", current_time)

        #call the auxiliary function _clust_class for long duration
        self._clust_class("long")

        self.training_phase = True

    def loading(self):
        #LOAD INFORMATION FROM TE_DC_PARAMETERS TABLE
        ps_cur, conn = DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).connect()
        ps_cur.execute("SELECT * FROM TE_DC_PARAMETERS;")
        query=ps_cur.fetchall()
        ##disconnect from the database
        DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).disconnect(conn)

        #load the parameters of the module that were saved at the training phase
        self._old_ip_devices = []
        self._old_ip_devices.append(TE_DC.data_integrity(pickle.loads(query[0][1])))
        self._old_ip_devices.append(TE_DC.data_integrity(pickle.loads(query[0][1])))
        self._old_bt_devices = []
        self._old_bt_devices.append(TE_DC.data_integrity(pickle.loads(query[1][1])))
        self._old_bt_devices.append(TE_DC.data_integrity(pickle.loads(query[1][1])))  
        self._old_zw_devices = []
        self._old_zw_devices.append(TE_DC.data_integrity(pickle.loads(query[2][1])))
        self._old_zw_devices.append(TE_DC.data_integrity(pickle.loads(query[2][1])))
        self._old_rf_devices = []
        self._old_rf_devices.append(TE_DC.data_integrity(pickle.loads(query[3][1])))
        self._old_rf_devices.append(TE_DC.data_integrity(pickle.loads(query[3][1])))
        self._old_zb_devices = []
        self._old_zb_devices.append(TE_DC.data_integrity(pickle.loads(query[4][1])))
        self._old_zb_devices.append(TE_DC.data_integrity(pickle.loads(query[4][1])))
        self._clusters = []
        self._clusters.append(pickle.loads(query[5][1]))
        self._clusters.append(pickle.loads(query[9][1]))
        self._templates = []
        self._templates.append(pickle.loads(query[6][1]))
        self._templates.append(pickle.loads(query[10][1]))
        self._distances = []
        self._distances.append(pickle.loads(query[7][1]))
        self._distances.append(pickle.loads(query[11][1]))
        self._classification_model = []
        self._classification_model.append(pickle.loads(query[8][1]))
        self._classification_model.append(pickle.loads(query[12][1]))
        self._clusters_ip = []
        self._clusters_ip.append(self._clusters[0][0:len(self._old_ip_devices[0])])
        self._clusters_ip.append(self._clusters[1][0:len(self._old_ip_devices[0])])
        self._clusters_bt = []
        self._clusters_bt.append(self._clusters[0][len(self._old_ip_devices[0]):len(self._old_ip_devices[0]) + len(self._old_bt_devices[0])])
        self._clusters_bt.append(self._clusters[1][len(self._old_ip_devices[1]):len(self._old_ip_devices[1]) + len(self._old_bt_devices[1])])
        self._clusters_zw = []
        self._clusters_zw.append(self._clusters[0][len(self._old_ip_devices[0]) + len(self._old_bt_devices[0]):len(self._old_ip_devices[0]) + 
                            len(self._old_bt_devices[0]) + len(self._old_zw_devices[0])])
        self._clusters_zw.append(self._clusters[1][len(self._old_ip_devices[1]) + len(self._old_bt_devices[1]):len(self._old_ip_devices[1]) + 
                            len(self._old_bt_devices[1]) + len(self._old_zw_devices[1])])
        self._clusters_rf = []
        self._clusters_rf.append(self._clusters[0][len(self._old_ip_devices[0]) + len(self._old_bt_devices[0]) + len(self._old_zw_devices[0]):len(self._old_ip_devices[0]) + 
                            len(self._old_bt_devices[0]) + len(self._old_zw_devices[0]) + len(self._old_rf_devices[0])])
        self._clusters_rf.append(self._clusters[1][len(self._old_ip_devices[1]) + len(self._old_bt_devices[1]) + len(self._old_zw_devices[1]):len(self._old_ip_devices[1]) + 
                            len(self._old_bt_devices[1]) + len(self._old_zw_devices[1]) + len(self._old_rf_devices[1])])
        self._clusters_zb = []
        self._clusters_zb.append(self._clusters[0][len(self._old_ip_devices[0]) + len(self._old_bt_devices[0]) + len(self._old_zw_devices[0]) +
                            len(self._old_rf_devices[0]):len(self._clusters[0])])
        self._clusters_zb.append(self._clusters[1][len(self._old_ip_devices[1]) + len(self._old_bt_devices[1]) + len(self._old_zw_devices[1]) +
                            len(self._old_rf_devices[1]):len(self._clusters[1])])

        self.loading_phase = True      
        
    def running_short(self):
        self._running("short")
    
    def running_long(self):
        self._running("long")
        
    def _running(self, duration):
        logging.info("=====================================")
        logging.info("MONITORING PHASE")
        logging.info("=====================================")
                
        #get the current devices
        ip_devices, bt_devices, zw_devices, rf_devices, zb_devices = GD(self.config).get_devices()
        all_devices = GD(self.config).get_all()

        if duration == "short":
            index = 0
        else:
            index = 1

        #initialization of empty lists for new devices
        new_ip_devices, new_bt_devices, new_zw_devices, new_rf_devices, new_zb_devices = ([] for i in range(5))
        #check for new devices
        if not np.array_equal(self._old_ip_devices[index], TE_DC.data_integrity(ip_devices)):
            new_ip_devices = GD(self.config).new_devices(self._old_ip_devices[index], TE_DC.data_integrity(ip_devices), new_ip_devices)
        if not np.array_equal(self._old_bt_devices[index], TE_DC.data_integrity(bt_devices)):
            new_bt_devices = GD(self.config).new_devices(self._old_bt_devices[index], TE_DC.data_integrity(bt_devices), new_bt_devices)
        if not np.array_equal(self._old_zw_devices[index], TE_DC.data_integrity(zw_devices)):
            new_zw_devices = GD(self.config).new_devices(self._old_zw_devices[index], TE_DC.data_integrity(zw_devices), new_zw_devices)
        if not np.array_equal(self._old_rf_devices[index], TE_DC.data_integrity(rf_devices)):
            new_rf_devices = GD(self.config).new_devices(self._old_rf_devices[index], TE_DC.data_integrity(rf_devices), new_rf_devices)
        if not np.array_equal(self._old_zb_devices[index], TE_DC.data_integrity(zb_devices)):
            new_zb_devices = GD(self.config).new_devices(self._old_zb_devices[index], TE_DC.data_integrity(zb_devices), new_zb_devices)

        #update the old devices
        self._old_ip_devices[index] = TE_DC.data_integrity(ip_devices)
        self._old_bt_devices[index] = TE_DC.data_integrity(bt_devices)
        self._old_zw_devices[index] = TE_DC.data_integrity(zw_devices)
        self._old_rf_devices[index] = TE_DC.data_integrity(rf_devices)
                              
        if new_ip_devices or new_bt_devices or new_zw_devices or new_rf_devices or new_zb_devices:
            #call function that requests to CR_CE 
            self._request_CR_CE(new_ip_devices, new_bt_devices, new_zw_devices, new_rf_devices, new_zb_devices, "running_" + duration)
            if self.runner:
                ########################CLASSIFICATION###################################
                #only if a classification model exists
                if self._classification_model[index] != None:
                    #classify the new devices
                    for i, prob in enumerate(self._classification_model[index].predict_proba(self.red_data)):
                        #if the classification model is confident about its prediction use the prediction
                        if np.max(prob) > 0.7:
                            if i < len (new_ip_devices):
                                self._clusters_ip[index] = np.append (self._clusters_ip[index], self._classification_model[index].predict(self.red_data[i].reshape(1,-1))[0])
                            elif i < len (new_ip_devices + new_bt_devices):
                                self._clusters_bt[index] = np.append (self._clusters_bt[index], self._classification_model[index].predict(self.red_data[i].reshape(1,-1))[0])
                            elif i < len (new_ip_devices + new_bt_devices + new_zw_devices):
                                self._clusters_zw[index] = np.append (self._clusters_zw[index], self._classification_model[index].predict(self.red_data[i].reshape(1,-1))[0])
                            elif i < len (new_ip_devices + new_bt_devices + new_zw_devices + new_rf_devices):
                                self._clusters_rf[index] = np.append (self._clusters_rf[index], self._classification_model[index].predict(self.red_data[i].reshape(1,-1))[0])
                            else:
                                self._clusters_zb[index] = np.append (self._clusters_zb[index], self._classification_model[index].predict(self.red_data[i].reshape(1,-1))[0])
                        #else create a new cluster
                        else:
                            if i < len (new_ip_devices):
                                self._clusters_ip[index] = np.append(self._clusters_ip[index], np.max(self._clusters[index]) + 1)
                            elif i < len (new_ip_devices + new_bt_devices):
                                self._clusters_bt[index] = np.append(self._clusters_bt[index], np.max(self._clusters) + 1)
                            elif i < len (new_ip_devices + new_bt_devices + new_zw_devices):
                                self._clusters_zw[index] = np.append(self._clusters_zw[index], np.max(self._clusters[index]) + 1)
                            elif i < len (new_ip_devices + new_bt_devices + new_zw_devices + new_rf_devices):
                                self._clusters_rf[index] = np.append(self._clusters_rf[index], np.max(self._clusters[index]) + 1)
                            else:
                                self._clusters_zb[index] = np.append(self._clusters_zb[index], np.max(self._clusters[index]) + 1)
                            self._templates[index] = np.vstack((self._templates[index], self.red_data[i]))
                            self._distances[index] = np.append(self._distances[index], 1)
                        self._clusters[index] = np.append(np.append(np.append(np.append(self._clusters_ip[index], self._clusters_bt[index]),
                                         self._clusters_zw[index]), self._clusters_rf[index]), self._clusters_zb[index])
                else:
                    for i, rd in enumerate(self.red_data):
                        if i < len (new_ip_devices):
                            self._clusters_ip[index] = np.append(self._clusters_ip[index], 1)
                        elif i < len (new_ip_devices + new_bt_devices):
                            self._clusters_bt[index] = np.append(self._clusters_bt[index], 1)
                        elif i < len (new_ip_devices + new_bt_devices + new_zw_devices):
                            self._clusters_zw[index] = np.append(self._clusters_zw[index], 1)
                        elif i < len (new_ip_devices + new_bt_devices + new_zw_devices + new_rf_devices):
                            self._clusters_rf[index] = np.append(self._clusters_rf[index], 1)
                        else:
                            self._clusters_zb[index] = np.append(self._clusters_zb[index], 1)
                        self._templates[index] = np.vstack((self._templates[index], self.red_data[i]))
                        self._distances[index] = np.append(self._distances[index], 1)
                        self._clusters[index] = np.append(np.append(np.append(np.append(self._clusters_ip[index], self._clusters_bt[index]),
                                         self._clusters_zw[index]), self._clusters_rf[index]), self._clusters_zb[index])

        #call function that requests to CR_CE 
        self._request_CR_CE(TE_DC.data_integrity(ip_devices), TE_DC.data_integrity(bt_devices),
                            TE_DC.data_integrity(zw_devices), TE_DC.data_integrity(rf_devices),
                            TE_DC.data_integrity(zb_devices), "running_" + duration)
        if self.runner:
            #check for abnomral behavior
            AD().anomaly_detection(self._communicator, self.red_data, self._clusters[index], self._templates[index], all_devices, self._distances[index], duration)
    #function for data integrity
    @staticmethod
    def data_integrity(table):
        if len(table):
            result = table[:,0]
        else:
            result = []
        return result

    #function for requesting to CR_CE
    def _request_CR_CE(self, ip_devices, bt_devices, zw_devices, rf_devices, zb_devices, phase, current_time = None):
        devices =  CR_CE_Devices()
        for ip in ip_devices:
            devices.ip_devices.ip.append(ip)
        for bt in bt_devices:
            devices.bt_devices.bt.append(bt)
        for zw in zw_devices:
            devices.zw_devices.zw.append(zw)
        for rf in rf_devices:
            devices.rf_devices.rf.append(rf)
        for zb in zb_devices:
            devices.zb_devices.zb.append(zb)

        self.red_data = np.asarray([])
        self.training_data = np.asarray([])
        if phase.startswith("running"):
            self._communicator.request("cr_ce", phase, devices.SerializeToString(), self._on_reply_running)
            
        else:
            devices.timestamp = current_time
            self._communicator.request("cr_ce", phase, devices.SerializeToString(), self._on_reply_training, timeout = 10800)
        while not(self.red_data.any()) and self.runner:
            try:
                time.sleep(1)
            except Exception:
                pass  

    def _clust_class(self, duration):
        if self.runner:
            #use DBSCAN clustering algorith to group devices
            clustering = DBSCAN(eps = 1, min_samples = 1).fit(self.red_data)

            final_clusters = clustering.labels_

            #FINDING CENTER OF CLUSTER - TEMPLATE EXTRACTION
            templates = TEMPLATE_EXTRACTION(config).TE(final_clusters, self.red_data, duration)

            #FINDING DISTANCES PER CLUSTER - TEMPLATE EXTRACTION
            distances = TEMPLATE_EXTRACTION(config).DST_CL(final_clusters, templates, self.training_data)

            ################################DATA CLASSIFICATION WITH A VOTING CLASSIFFIER#########################################

            man_classes=np.asarray(final_clusters)
            #TRAINING OF ENSEMBLE CLASSIFIER
            #only if there are at least two clusters
            if (np.max(final_clusters) > 0):
                classification_model = EC().ensemble_training(self.red_data, man_classes)
            else:
                classification_model = None

            #save clusters, templates and classification model to db in byte format
            ps_cur, conn = DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).connect()
            ps_cur.execute("INSERT INTO te_dc_parameters VALUES (%s, %s);",("clusters_" + duration, pickle.dumps(final_clusters)))
            ps_cur.execute("INSERT INTO te_dc_parameters VALUES (%s, %s);",("templates_" + duration, pickle.dumps(templates)))
            ps_cur.execute("INSERT INTO te_dc_parameters VALUES (%s, %s);",("distances_" + duration, pickle.dumps(distances)))
            ps_cur.execute("INSERT INTO te_dc_parameters VALUES (%s, %s);",("cf_model_" + duration, pickle.dumps(classification_model)))
            conn.commit()
            #disconnect from the database
            DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).disconnect(conn)

    @staticmethod
    def _on_reply_running(data): 
        red_data = ReducedData()
        red_data.ParseFromString(data)
        te_dc.red_data = []
        for i, rd, in enumerate(red_data.device_data):
            temp = []
            for vl in rd.value:
                temp.append(vl)
            te_dc.red_data.append(temp)
        te_dc.red_data = np.asarray(te_dc.red_data)

    @staticmethod
    def _on_reply_training(data): 
        full_data = FullData()
        full_data.ParseFromString(data)
        te_dc.training_data = []
        #fill the training data
        for td in full_data.training_data:
            temp_red_data = []
            for rd in td.device_data:
                temp = []
                for vl in rd.value:
                    temp.append(vl)
                temp_red_data.append(temp)
            te_dc.training_data.append(np.asarray(temp_red_data))
                
        te_dc.red_data = []
        #fill the reduced data
        for rd in full_data.reduced_data.device_data:
            temp = []
            for vl in rd.value:
                temp.append(vl)
            te_dc.red_data.append(temp)
        te_dc.red_data = np.asarray(te_dc.red_data)

    def stop(self):
        self.runner = False
        self._communicator.stop()
        

def signal_handler(signum, frame):
    """Signal handler which stops the TE_DC module upon reception of a signal."""
    logging.info('Signal received: stopping...')
    te_dc.stop()
    logging.shutdown()


if __name__ == '__main__':
    logging.info("Reading command line arguments.")
    sys.path.append(os.getcwd())
    
    parser = argparse.ArgumentParser(description="The TE_DC module.")
    parser.add_argument(
        "--version", help="display the version",
        action="version", version="%(prog)s {}".format(__version__))
    parser.add_argument(
        "--config", "-c",
        help="the path and name of the configuration file",
        required=True)
    args = parser.parse_args()
    config = get_configuration(args.config)
    te_dc = TE_DC(config)
    
    if sys.platform.startswith('linux'):
        signal.signal(signal.SIGQUIT, signal_handler)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    #Scheduling of the jobs
    schedule.every().day.at(te_dc.start).do(te_dc.training)
    schedule.every().day.at(te_dc.start).do(te_dc.loading)
    
    while not te_dc.training_phase and te_dc.runner:
        schedule.run_pending()
        try:
            time.sleep(1)
        except Exception:
            pass

    if (not te_dc.loading_phase and te_dc.runner):
        te_dc.loading()

    schedule.every(int(te_dc.interval)).seconds.do(te_dc.running_short)
    schedule.every(int(te_dc.interval)).seconds.do(te_dc.running_long)

    while te_dc.runner:
        schedule.run_pending()
        try:
            time.sleep(30)
        except Exception:
            pass
    