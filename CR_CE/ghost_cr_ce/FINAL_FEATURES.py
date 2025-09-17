from communication_events import CR_CE
from FEATURE_EXTRACTION import FEATURE_EXTRACTION
from DATABASE_COMMUNICATION import DBC
from DATA_PREPROCESSING import DP
import sys, os
from psycopg2.extras import Json
sys.path.append(os.path.relpath(os.path.join('../communication_protocols/python')))
from ghost_protocol.utils import get_configuration
import pickle
import numpy as np

class FF:
    def __init__(self, config):
        self.config = config
        self._db_name = self.config.get("Database", "name")
        self._db_user = self.config.get("Database", "user")
        self._db_password = self.config.get("Database", "password")
        self._db_host = self.config.get("Database", "host")
        self._db_port = self.config.get("Database", "port")
        self._instances_total_features = []

    def training_final_features(self, ip_devices, bt_devices, zw_devices, rf_devices, zb_devices, current_time, last_time, interval, duration):
        #call the final_features function
        final_features = self.final_features (ip_devices, bt_devices, zw_devices, rf_devices, zb_devices, current_time, last_time, interval)
        #call the data_preprocessing function in order to standardize and reduce the dataset
        red_data, scaler, pca = DP().data_preprocessing(final_features)

        for i, itf in enumerate(self._instances_total_features):
            #standardize the features
            self._instances_total_features[i] = scaler.transform(self._instances_total_features[i])
            #apply PCA to reduce the space
            self._instances_total_features[i] = pca.transform(self._instances_total_features[i])
                    
        #connect to the database
        ps_cur, conn = DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).connect()
        #save scaler and pca to db in byte format
        ps_cur.execute("INSERT INTO cr_ce_parameters VALUES (%s, %s);",("scaler_" + duration, pickle.dumps(scaler)))
        ps_cur.execute("INSERT INTO cr_ce_parameters VALUES (%s, %s);",("pca_" + duration, pickle.dumps(pca)))
        conn.commit()
        #disconnect from the database
        DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).disconnect(conn) 
        
        return(red_data, self._instances_total_features)

    def running_final_features(self, ip_devices, bt_devices, zw_devices, rf_devices, zb_devices, current_time, last_time, interval, duration):
        #call the final_features function
        final_features = self.final_features(ip_devices, bt_devices, zw_devices, rf_devices, zb_devices, current_time, last_time, interval)
        #get the pca and the scaler from db table
        ps_cur, conn = DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).connect()
        ps_cur.execute("SELECT * FROM CR_CE_PARAMETERS;")
        query=ps_cur.fetchall()
        #disconnect from the database
        DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).disconnect(conn)
        if duration == "short":
            scaler = pickle.loads(query[0][1])
            pca = pickle.loads(query[1][1])
        else: 
            scaler = pickle.loads(query[2][1])
            pca = pickle.loads(query[3][1])
        #standardize the features
        final_features = scaler.transform(final_features)
        #apply PCA to reduce the space
        final_features = pca.transform(final_features)
        
        return(final_features)

    def final_features(self, ip_devices, bt_devices, zw_devices, rf_devices, zb_devices, current_time, last_time, interval):
        #connect to the database
        ps_cur, conn = DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).connect()
        ps_cur.execute("TRUNCATE TABLE features RESTART IDENTITY;")
        #disconnect from the database
        DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).disconnect(conn)
               
        #define the number of the past time intervals
        iterations = int((current_time - last_time) / interval)

        #starting and ending time for the initial step
        end = current_time
        start = current_time - interval

        #initialize list instances_events & instances_features that will contain all the data from the time intervals
        instances_events = []
        instances_features = []

        #start of the loop
        for i in range(iterations):

            ps_cur, conn = DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).connect()
            ps_cur.execute("TRUNCATE TABLE events RESTART IDENTITY;")
            #disconnect from the database
            DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).disconnect(conn)

            #initialize table event_fetures
            event_features = []
            event_features = CR_CE(self.config).CR_CE_execution(event_features, ip_devices, bt_devices, zw_devices, rf_devices, zb_devices, end, start)
            instances_events.append(event_features)

            #initialize table fetures (packet-level features)
            features = []
            features = FEATURE_EXTRACTION(self.config).FEATURE_EXTRACTION_execution(features, ip_devices, bt_devices, zw_devices, rf_devices, zb_devices, end, start)
            instances_features.append(features)

            #change the start and end points for the next iteration
            end -= interval
            start -= interval

        
        #only for the instances > 1
        if len(instances_events) > 1:
            features = [[None] * len(instances_features[0][0]) for i in range(len(instances_features[0]))]
            event_features = [[None] * len(instances_events[0][0]) for i in range(len(instances_events[0]))]
            #get the mean of these two instance lists as the prediction of the different time-series
            for j in range(len(instances_events[0])):
                for k in range(len(instances_features[0][0])):
                    if k < len(instances_features[0][0]) - 1:
                        temp1 = []
                    temp2 = []
                    for i in range(len(instances_events)):
                        if k < len(instances_features[0][0]) - 1:
                            temp1.append(instances_events[i][j][k])    
                        temp2.append(instances_features[i][j][k])
                    if k < len(instances_features[0][0]) - 1:
                        event_features[j][k] = np.mean(temp1)
                    features[j][k] = np.mean(temp2)
        
            #fill the instances_total_features table that will contain the final features for all the instances of the training
            for i_feat, i_ev in zip (instances_features, instances_events):
                total_features = []
                for f, ef in zip(i_feat, i_ev): 
                    total_features.append(f + ef)
                self._instances_total_features.append(total_features)
            #create the final features by combining the features (packet-level metrics) and the event_features
            final_features = []
            for f, ef in zip(features, event_features): 
                final_features.append(f + ef)
        else:
            #create the final features by combining the features (packet-level metrics) and the event_features
            final_features = []
            for f, ef in zip(features, event_features): 
                final_features.append(f + ef)
            self._instances_total_features = final_features

        
        #initialize feature list that will contain the stats from final_features along with the corresponding label 
        feature = {}
        ps_cur, conn = DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).connect()
        for dev in final_features: 
            #fill the feature list with the previously calculated statistics
            for j, st in enumerate(dev):
                feature[(FEATURE_EXTRACTION(self.config).feature_values + CR_CE(self.config).event_feature_values)[j]] = st
            ps_cur.execute("INSERT INTO features (feature) VALUES ({});".format(Json(feature)))            
        #disconnect from the database
        DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).disconnect(conn)
        
        return(final_features)

    def get_context(self, templates, new_data, duration):
        #get the pca and the scaler from db table
        ps_cur, conn = DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).connect()
        ps_cur.execute("SELECT * FROM CR_CE_PARAMETERS;")
        query=ps_cur.fetchall()
        #disconnect from the database
        DBC(self._db_name, self._db_user, self._db_password, self._db_host, self._db_port).disconnect(conn)
        if duration == "short":
            pca = pickle.loads(query[1][1])
        else: 
            pca = pickle.loads(query[3][1])
        templates = pca.inverse_transform(templates)
        new_data = pca.inverse_transform(new_data)
        min_diff = new_data[0] - templates[0]
        min_position = 0
        max_diff = new_data[0] - templates[0]
        max_position = 0

        for i in range (1, len(new_data)):
            if new_data[i] - templates[i] < min_diff:
                min_diff = new_data[i] - templates[i]
                min_position = i
            if new_data[i] - templates[i] > max_diff:
                max_diff = new_data[i] - templates[i]
                max_position = i
        list_values = FEATURE_EXTRACTION(self.config).feature_values + CR_CE(self.config).event_feature_values
        if abs(min_diff) > max_diff:
            return("Decrease in " + list_values[min_position])
        else:
            return("Increase in " + list_values[max_position])