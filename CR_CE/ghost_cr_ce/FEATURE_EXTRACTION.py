from psycopg2.extras import Json
import numpy as np
from DATABASE_COMMUNICATION import DBC


class FEATURE_EXTRACTION:
    #iniitalization
    def __init__(self, config):
        #the values of the feature table
        self.feature_values = ['Minimum packet size in bytes', 'Maximum packet size in bytes', 'First quartile of size in bytes', 'Median of size in bytes', 'Mean of size in bytes',
        'Third quartile of size in bytes', 'Standard deviation of size in bytes', 'Inter quartile range of size in bytes', 'Minimum packet inter-arrival time',
        'Maximum packet inter-arrival time', 'First quartile of inter-arrival time', 'Median of inter-arrival time', 'Mean of inter-arrival time', 'Third quartile of inter-arrival time',
        'Standard deviation of inter-arrival time', 'Inter quartile range of inter-arrival time', 'Number of Packets', 'Number of Personal Packets']
        self.name = config.get("Database", "name")
        self.user = config.get("Database", "user")
        self.password = config.get("Database", "password")
        self.host = config.get("Database", "host")
        self.port = config.get("Database", "port")
            
    
    def FEATURE_EXTRACTION_IP(self, current_time, last_time, reg_devices, feature_classification):

        for rd in reg_devices:
            stat_table = [0] * len(self.feature_values)
            #connect to Database as context_reasoning
            ps_cur, conn = DBC(self.name, self.user, self.password, self.host, self.port).connect()

            ps_cur.execute("SELECT id FROM ipv4_packets WHERE ((data->>'src_ip'=%s OR data->>'dst_ip' = %s)  AND data->>'data' != %s AND (data->>'time' > '%s' AND data->>'time' < '%s')) ORDER BY data->>'time';",(rd, rd, '\'\'', last_time, current_time))
            IDs_sent_received = ps_cur.fetchall()
            number_of_personal_packets = len(IDs_sent_received)
            

            #------------------------------------------------------------

            #SIZE OF PACKETS (TOTAL)
    
            ps_cur.execute("SELECT data->>'length' FROM ipv4_packets WHERE ((data->>'src_ip'=%s OR data->>'dst_ip'=%s) AND (data->>'time' > '%s' AND data->>'time' < '%s')) ORDER BY data->>'time';",(rd, rd, last_time, current_time))
            packet_size = ps_cur.fetchall()

            x=[]
            datasize=0
            for ps in packet_size:
                temp = int(ps[0])
                x.append(temp)
                datasize += temp
                                
            x = np.asarray(x)
            #check that the array has values
            if len(x) > 0:
                stat_table[0] = min(x)
                stat_table[1] = max(x)
                stat_table[2] = np.percentile(x, 25)
                stat_table[3] = np.percentile(x, 50)
                stat_table[4] = np.mean(x)
                stat_table[5] = np.percentile(x, 75)
                stat_table[6] = np.std(x)
                stat_table[7] = stat_table[5] - stat_table[2]
                stat_table[16] = len(x)
                stat_table[17] = number_of_personal_packets
       
            #------------------------------------------------------------

            #DURATION BETWEEN PERSONAL PACKET TRANSMITION

            ps_cur.execute("SELECT data->>'time' FROM ipv4_packets WHERE ((data->>'src_ip'=%s OR data->>'dst_ip'=%s) AND (data->>'time' > '%s' AND data->>'time' < '%s')) ORDER BY data->>'time';",(rd, rd, last_time, current_time))
            
            timestamps_packets = ps_cur.fetchall()
            #close connection with the db
            DBC(self.name, self.user, self.password, self.host, self.port).disconnect(conn)
            
            x = []
            num_packets = len(timestamps_packets)
            if num_packets == 0:
                x.append(current_time - last_time)

            elif num_packets == 1:
                x.append(float(timestamps_packets[0][0]) - last_time)
                x.append(current_time - float(timestamps_packets[0][0]))
            else:
                x.append(float(timestamps_packets[0][0]) - last_time)
                for j in range(1, num_packets):
                    temp = float(timestamps_packets[j][0]) - float(timestamps_packets[j - 1][0])
                    x.append(temp)
                x.append(current_time - float(timestamps_packets[0][0]))
                
            x = np.asarray(x)
            stat_table[8] = min(x)
            stat_table[9] = max(x)
            stat_table[10] = np.percentile(x, 25)
            stat_table[11] = np.percentile(x, 50)
            stat_table[12] = np.mean(x)
            stat_table[13] = np.percentile(x, 75)
            stat_table[14] = np.std(x)
            stat_table[15] = stat_table[13] - stat_table[10]
  
            feature_classification.append(stat_table)
           
        return(feature_classification)
      
    
    #-------------------------------------------------------
    #Bluetooth devices

    def FEATURE_EXTRACTION_BT(self, current_time, last_time, reg_devices, feature_classification):
        for dev in reg_devices:
            #initialize stat_table
            stat_table = [0] * len(self.feature_values)
            ps_cur, conn = DBC(self.name, self.user, self.password, self.host, self.port).connect()

            #Select the size of all the packets
            ps_cur.execute("SELECT data->>'length' FROM bt_packets WHERE ((data->>'src_bd_addr'=%s OR data->>'dst_bd_addr'=%s) AND (data->>'time' > '%s' AND data->>'time' < '%s')) ORDER BY id;",(dev, dev, last_time, current_time))
            packet_size = ps_cur.fetchall()
                
            x = []
            datasize = 0
            for ps in packet_size:
                temp = int(ps[0])
                x.append(temp)
                datasize += temp

            x = np.asarray(x)
            #check that the array has values
            if len(x) > 0:
                stat_table[0] = min(x)
                stat_table[1] = max(x)
                stat_table[2] = np.percentile(x, 25)
                stat_table[3] = np.percentile(x, 50)
                stat_table[4] = np.mean(x)
                stat_table[5] = np.percentile(x, 75)
                stat_table[6] = np.std(x)
                stat_table[7] = stat_table[5] - stat_table[2]
                stat_table[16] = len(x)
                stat_table[17] = len(x)
            
            #DURATION BETWEEN PACKET TRANSMITION
            ps_cur.execute("SELECT data->>'time' FROM bt_packets WHERE ((data->>'src_bd_addr'=%s OR data->>'dst_bd_addr'=%s) AND (data->>'time' > '%s' AND data->>'time' < '%s')) ORDER BY data->>'time';", (dev, dev, last_time, current_time))
            timestamps_packets = ps_cur.fetchall()
            DBC(self.name, self.user, self.password, self.host, self.port).disconnect(conn)
        
            x = []
            num_packets = len(timestamps_packets)
            if num_packets == 0:
                x.append(current_time - last_time)

            elif num_packets == 1:
                x.append(float(timestamps_packets[0][0]) - last_time)
                x.append(current_time - float(timestamps_packets[0][0]))
            else:
                x.append(float(timestamps_packets[0][0]) - last_time)
                for j in range(1, num_packets):
                    temp = float(timestamps_packets[j][0]) - float(timestamps_packets[j - 1][0])
                    x.append(temp)
                x.append(current_time - float(timestamps_packets[0][0]))
                
            x = np.asarray(x)
            stat_table[8] = min(x)
            stat_table[9] = max(x)
            stat_table[10] = np.percentile(x, 25)
            stat_table[11] = np.percentile(x, 50)
            stat_table[12] = np.mean(x)
            stat_table[13] = np.percentile(x, 75)
            stat_table[14] = np.std(x)
            stat_table[15] = stat_table[13] - stat_table[10]
            
            feature_classification.append(stat_table)
            
        return(feature_classification)


    #----------------------------------------------------------------------------
    #Z-WAVE devices

    def FEATURE_EXTRACTION_ZW(self, current_time, last_time, reg_devices, feature_classification):

       
        for dev in reg_devices:
            #initialize stat_table
            stat_table = [0] * len(self.feature_values)
            
            ps_cur, conn = DBC(self.name, self.user, self.password, self.host, self.port).connect()
            
            #Select the size of all the packets
            ps_cur.execute("SELECT data->>'length' FROM zw_packets WHERE ((substr(data->>'src_zw_addr', 2, 1) = %s OR substr(data->>'src_zw_addr', 5, 1) = %s) AND (data->>'time' > '%s' AND data->>'time' < '%s')) ORDER BY id;",(dev, dev, last_time, current_time))
            packet_size = ps_cur.fetchall()
                        
            x=[]
            datasize=0
            for ps in packet_size:
                temp = int(ps[0])
                x.append(temp)
                datasize += temp

            x = np.asarray(x)
            #check that the array has values
            if len(x) > 0:
                stat_table[0] = min(x)
                stat_table[1] = max(x)
                stat_table[2] = np.percentile(x, 25)
                stat_table[3] = np.percentile(x, 50)
                stat_table[4] = np.mean(x)
                stat_table[5] = np.percentile(x, 75)
                stat_table[6] = np.std(x)
                stat_table[7] = stat_table[5] - stat_table[2]
                stat_table[16] = len(x)
                stat_table[17] = len(x)
            #DURATION BETWEEN PACKET TRANSMITION
            ps_cur.execute("SELECT data->>'time' FROM zw_packets WHERE ((substr(data->>'src_zw_addr', 2, 1) = %s OR substr(data->>'src_zw_addr', 5, 1) = %s) AND (data->>'time' > '%s' AND data->>'time' < '%s')) ORDER BY data->>'time';", (dev, dev, last_time, current_time))
            timestamps_packets = ps_cur.fetchall()
            DBC(self.name, self.user, self.password, self.host, self.port).disconnect(conn)
            
            x = []
            num_packets = len(timestamps_packets)
            if num_packets == 0:
                x.append(current_time - last_time)

            elif num_packets == 1:
                x.append(float(timestamps_packets[0][0]) - last_time)
                x.append(current_time - float(timestamps_packets[0][0]))
            else:
                x.append(float(timestamps_packets[0][0]) - last_time)
                for j in range(1, num_packets):
                    temp = float(timestamps_packets[j][0]) - float(timestamps_packets[j - 1][0])
                    x.append(temp)
                x.append(current_time - float(timestamps_packets[0][0]))
                
            x = np.asarray(x)
            stat_table[8] = min(x)
            stat_table[9] = max(x)
            stat_table[10] = np.percentile(x, 25)
            stat_table[11] = np.percentile(x, 50)
            stat_table[12] = np.mean(x)
            stat_table[13] = np.percentile(x, 75)
            stat_table[14] = np.std(x)
            stat_table[15] = stat_table[13] - stat_table[10]
            
            feature_classification.append(stat_table)
        
        return(feature_classification)

    #----------------------------------------------------------------------------
    #RF869 devices
    
    def FEATURE_EXTRACTION_RF(self, current_time, last_time, reg_devices, feature_classification):

       
        for dev in reg_devices:
            #initialize stat_table
            stat_table = [0] * len(self.feature_values)
            
            ps_cur, conn = DBC(self.name, self.user, self.password, self.host, self.port).connect()
            
            #Select the size of all the packets
            ps_cur.execute("SELECT data->>'length' FROM rf869_packets WHERE (data->>'address' = %s AND (data->>'time' > '%s' AND data->>'time' < '%s')) ORDER BY id;",(dev, last_time, current_time))
            packet_size = ps_cur.fetchall()
                        
            x=[]
            datasize=0
            for ps in packet_size:
                temp = int(ps[0])
                x.append(temp)
                datasize += temp

            x = np.asarray(x)
            #check that the array has values
            if len(x) > 0:
                stat_table[0] = min(x)
                stat_table[1] = max(x)
                stat_table[2] = np.percentile(x, 25)
                stat_table[3] = np.percentile(x, 50)
                stat_table[4] = np.mean(x)
                stat_table[5] = np.percentile(x, 75)
                stat_table[6] = np.std(x)
                stat_table[7] = stat_table[5] - stat_table[2]
                stat_table[16] = len(x)
            #personal packets
            ps_cur.execute("SELECT id FROM rf869_packets WHERE (data->>'address' = %s AND (data->>'time' > '%s' AND data->>'time' < '%s' AND (data->>'type' = '60' OR data->>'type' = '61'))) ORDER BY id;",(dev, last_time, current_time))
            personal_packets = ps_cur.fetchall()
            stat_table[17] = len(personal_packets)
            #DURATION BETWEEN PACKET TRANSMITION
            ps_cur.execute("SELECT data->>'time' FROM rf869_packets WHERE (data->>'address' = %s AND (data->>'time' > '%s' AND data->>'time' < '%s')) ORDER BY id;",(dev, last_time, current_time))
            timestamps_packets = ps_cur.fetchall()
            DBC(self.name, self.user, self.password, self.host, self.port).disconnect(conn)
            
            x = []
            num_packets = len(timestamps_packets)
            if num_packets == 0:
                x.append(current_time - last_time)

            elif num_packets == 1:
                x.append(float(timestamps_packets[0][0]) - last_time)
                x.append(current_time - float(timestamps_packets[0][0]))
            else:
                x.append(float(timestamps_packets[0][0]) - last_time)
                for j in range(1, num_packets):
                    temp = float(timestamps_packets[j][0]) - float(timestamps_packets[j - 1][0])
                    x.append(temp)
                x.append(current_time - float(timestamps_packets[0][0]))
                
            x = np.asarray(x)
            stat_table[8] = min(x)
            stat_table[9] = max(x)
            stat_table[10] = np.percentile(x, 25)
            stat_table[11] = np.percentile(x, 50)
            stat_table[12] = np.mean(x)
            stat_table[13] = np.percentile(x, 75)
            stat_table[14] = np.std(x)
            stat_table[15] = stat_table[13] - stat_table[10]
            
            feature_classification.append(stat_table)
        
        return(feature_classification)


    #-------------------------------------------------------
    #Zigbee devices

    def FEATURE_EXTRACTION_ZB(self, current_time, last_time, reg_devices, feature_classification):
        for dev in reg_devices:
            #initialize stat_table
            stat_table = [0] * len(self.feature_values)
            ps_cur, conn = DBC(self.name, self.user, self.password, self.host, self.port).connect()

            #Select the size of all the packets
            ps_cur.execute("SELECT data->>'length' FROM zgb_packets WHERE ((data->>'src_zb_addr'=%s OR data->>'dst_zb_addr'=%s) AND (data->>'time' > '%s' AND data->>'time' < '%s')) ORDER BY id;",(dev, dev, last_time, current_time))
            packet_size = ps_cur.fetchall()
                
            x = []
            datasize = 0
            for ps in packet_size:
                temp = int(ps[0])
                x.append(temp)
                datasize += temp

            x = np.asarray(x)
            #check that the array has values
            if len(x) > 0:
                stat_table[0] = min(x)
                stat_table[1] = max(x)
                stat_table[2] = np.percentile(x, 25)
                stat_table[3] = np.percentile(x, 50)
                stat_table[4] = np.mean(x)
                stat_table[5] = np.percentile(x, 75)
                stat_table[6] = np.std(x)
                stat_table[7] = stat_table[5] - stat_table[2]
                stat_table[16] = len(x)
                stat_table[17] = len(x)
            
            #DURATION BETWEEN PACKET TRANSMITION
            ps_cur.execute("SELECT data->>'time' FROM zgb_packets WHERE ((data->>'src_zb_addr'=%s OR data->>'dst_zb_addr'=%s) AND (data->>'time' > '%s' AND data->>'time' < '%s')) ORDER BY data->>'time';", (dev, dev, last_time, current_time))
            timestamps_packets = ps_cur.fetchall()
            DBC(self.name, self.user, self.password, self.host, self.port).disconnect(conn)
            
            x = []
            num_packets = len(timestamps_packets)
            if num_packets == 0:
                x.append(current_time - last_time)

            elif num_packets == 1:
                x.append(float(timestamps_packets[0][0]) - last_time)
                x.append(current_time - float(timestamps_packets[0][0]))
            else:
                x.append(float(timestamps_packets[0][0]) - last_time)
                for j in range(1, num_packets):
                    temp = float(timestamps_packets[j][0]) - float(timestamps_packets[j - 1][0])
                    x.append(temp)
                x.append(current_time - float(timestamps_packets[0][0]))
                
            x = np.asarray(x)
            stat_table[8] = min(x)
            stat_table[9] = max(x)
            stat_table[10] = np.percentile(x, 25)
            stat_table[11] = np.percentile(x, 50)
            stat_table[12] = np.mean(x)
            stat_table[13] = np.percentile(x, 75)
            stat_table[14] = np.std(x)
            stat_table[15] = stat_table[13] - stat_table[10]
            
            feature_classification.append(stat_table)
            
        return(feature_classification)



    def FEATURE_EXTRACTION_execution(self, features, ip_devices, bt_devices, zw_devices, rf_devices, zb_devices, current_time, last_time):

        #call the feature extraction functions for the three protocols
        features = self.FEATURE_EXTRACTION_IP(current_time,last_time, ip_devices, features)
        features = self.FEATURE_EXTRACTION_BT(current_time,last_time, bt_devices, features)
        features = self.FEATURE_EXTRACTION_ZW(current_time,last_time, zw_devices, features)
        features = self.FEATURE_EXTRACTION_RF(current_time,last_time, rf_devices, features)
        features = self.FEATURE_EXTRACTION_ZB(current_time,last_time, zb_devices, features)

        return(features)





