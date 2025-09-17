import numpy as np
from DATABASE_COMMUNICATION import DBC

class CR_CE:
    
    def __init__(self, config):
        #the values of the feature table
        self.event_feature_values = ['Minimum event-packets transmmited', 'Maximum event-packets transmmited', 'First quartile of event-packets transmmited', 'Median of event-packets transmmited', 'Mean of event-packets transmmited',
        'Third quartile of event-packets transmmited', 'Standard deviation of event-packets transmmited', 'Inter quartile range of event-packets transmmited', 'Minimum event-duration',
        'Maximum packet event-duration', 'First quartile of event-duration', 'Median of event-duration', 'Mean of event-duration', 'Third quartile of event-duration',
        'Standard deviation of event-duration', 'Inter quartile range of event-duration', 'Number of Different Events']
        self.name = config.get("Database", "name")
        self.user = config.get("Database", "user")
        self.password = config.get("Database", "password")
        self.host = config.get("Database", "host")
        self.port = config.get("Database", "port")


    #THIS FUNCTION IS USED TO CATEGORIZE SIMILAR EVENTS OF EACH DEVICE
    def CR_events_IP(self, current_time, last_time, features, reg_devices):
              
        #------------------------------------------------------------------------------
        #REGISTRY OF EVENTS
        
        feat_len = len(features)
        for rd in reg_devices:
            stat_table = [0] * len(self.event_feature_values)

            ps_cur, conn = DBC(self.name, self.user, self.password, self.host, self.port).connect()
            
            #NUMBER OF PACKETS SENT
            ps_cur.execute("SELECT data->>'packets_a' FROM ipv4_flows WHERE ((data->>'ip_a'=%s OR data->>'ip_b'=%s) AND data->>'status'=%s AND data->>'ts_end' > '%s' AND data->>'ts_end' < '%s') ORDER BY id;",(rd, rd, "expired", last_time, current_time))
            pack_sent = ps_cur.fetchall()
            #NUMBER OF PACKETS RECEIVED
            ps_cur.execute("SELECT data->>'packets_b' FROM ipv4_flows WHERE ((data->>'ip_a'=%s OR data->>'ip_b'=%s) AND data->>'status'=%s AND data->>'ts_end' > '%s' AND data->>'ts_end' < '%s') ORDER BY id;",(rd, rd,"expired", last_time, current_time))
            pack_received = ps_cur.fetchall()
            #TIMESTAMPS
            ps_cur.execute("SELECT data->>'ts_start' FROM ipv4_flows WHERE ((data->>'ip_a'=%s OR data->>'ip_b'=%s) AND data->>'status'=%s AND data->>'ts_end' > '%s' AND data->>'ts_end' < '%s') ORDER BY id;",(rd, rd, "expired", last_time, current_time))
            t_start = ps_cur.fetchall()

            ps_cur.execute("SELECT data->>'ts_end' FROM ipv4_flows WHERE ((data->>'ip_a'=%s OR data->>'ip_b'=%s) AND data->>'status'=%s AND data->>'ts_end' > '%s' AND data->>'ts_end' < '%s') ORDER BY id;",(rd, rd, "expired", last_time, current_time))
            t_end = ps_cur.fetchall()

            #disconnect from the database
            DBC(self.name, self.user, self.password, self.host, self.port).disconnect(conn)

            
            #connect to the database
            ps_cur, conn = DBC(self.name, self.user, self.password, self.host, self.port).connect()
            #FOR ALL NEW EVENTS FIND IF THEY ARE SIMILAR TO OLDER EVENTS IN ORDER TO GIVE THEM SAME EVENT_ID
            for ps, pr, ts, te in zip (pack_sent, pack_received, t_start, t_end):
                
                ps_cur.execute("SELECT event_id FROM events ORDER BY id;")
                all_event_ids = ps_cur.fetchall()
                if len(all_event_ids) > 0:
                    max_event_id = max(all_event_ids[:])
                    event_id = max_event_id[0] + 1
                else:
                    event_id = 1

                ps_cur.execute("SELECT event_id FROM events WHERE (device_reg_id = %s) ORDER BY id;", (feat_len + 1,))
                dev_event_ids = ps_cur.fetchall()
                ps_cur.execute("SELECT packets_transmitted FROM events WHERE (device_reg_id=%s) ORDER BY id;", (feat_len + 1,))
                dev_packs_transmitted = ps_cur.fetchall()
                ps_cur.execute("SELECT start_timestamp FROM events WHERE (device_reg_id=%s) ORDER BY id;", (feat_len + 1,))
                dev_start_timestamps = ps_cur.fetchall()
                ps_cur.execute("SELECT end_timestamp FROM events WHERE (device_reg_id=%s) ORDER BY id;", (feat_len + 1,))
                dev_end_timestamps = ps_cur.fetchall()


                for dei, dpt, dst, det in zip (dev_event_ids, dev_packs_transmitted, dev_start_timestamps, dev_end_timestamps):
                    if int(ps[0]) + int(pr[0]) == int(dpt[0]):
                        if abs((float(te[0]) - float(ts[0])) - (float(det[0]) - float(dst[0]))) < 1:
                            event_id = dei
                            break

                ps_cur.execute("INSERT INTO events (device_reg_id, packets_transmitted, start_timestamp, end_timestamp, event_id) VALUES (%s,%s,%s,%s,%s);",(feat_len + 1, ps[0] + pr[0], ts[0], te[0], event_id))
                conn.commit()
                
            ps_cur.execute("SELECT event_id, avg(packets_transmitted), avg(end_timestamp - start_timestamp) FROM events WHERE (device_reg_id = %s) GROUP BY event_id;", (feat_len + 1,))
            result = ps_cur.fetchall()
            DBC(self.name, self.user, self.password, self.host, self.port).disconnect(conn)
            
            #append the statistics of this device
            features.append(self.CR_statistics(stat_table, result, current_time, last_time))
            feat_len += 1
        return(features)

        
    def CR_events_BT_ZW_RF_ZB(self, current_time, last_time, features, reg_devices, pr):
        #------------------------------------------------------------------------------
        #REGISTRY OF EVENTS

        feat_len = len(features)
        for rd in reg_devices:
            stat_table = [0] * len(self.event_feature_values)    

            ps_cur, conn = DBC(self.name, self.user, self.password, self.host, self.port).connect()
            
            #NUMBER OF PACKETS SENT
            if pr == "bt":
                ps_cur.execute("SELECT data->>'number_of_packets', data->>'start_time', data->>'stop_time' FROM bt_batches WHERE ((data->>'src_bd_addr'= %s OR data->>'dst_bd_addr'=%s) AND data->>'stop_time' > '%s' AND data->>'stop_time' < '%s') ORDER BY id;",(rd, rd, last_time, current_time))
            elif pr == "zw":
                ps_cur.execute("SELECT data->>'number_of_packets', data->>'start_time', data->>'stop_time' FROM zw_batches WHERE ((substr(data->>'src_zw_addr', 2, 1) = %s OR substr(data->>'src_zw_addr', 5, 1) = %s ) AND data->>'stop_time' > '%s' AND data->>'stop_time' < '%s') ORDER BY id;",(rd, rd, last_time, current_time))
            elif pr == "rf":
                ps_cur.execute("SELECT data->>'number_of_packets', data->>'start_time', data->>'stop_time' FROM rf869_flows WHERE (data->>'address' = %s AND data->>'stop_time' > '%s' AND data->>'stop_time' < '%s') ORDER BY id;",(rd, last_time, current_time))
            elif pr == "zb":
                ps_cur.execute("SELECT data->>'number_of_packets', data->>'start_time', data->>'stop_time' FROM zgb_flows WHERE ((data->>'src_zb_addr'= %s OR data->>'dst_zb_addr'=%s) AND data->>'stop_time' > '%s' AND data->>'stop_time' < '%s') ORDER BY id;",(rd, rd, last_time, current_time))
            
            result = ps_cur.fetchall()
            result = np.asarray(result)
            
            #disconnect from the database
            DBC(self.name, self.user, self.password, self.host, self.port).disconnect(conn)

            #connect to the database
            ps_cur, conn = DBC(self.name, self.user, self.password, self.host, self.port).connect()
            
            #FOR ALL NEW EVENTS FIND IF THEY ARE SIMILAR TO OLDER EVENTS IN ORDER TO GIVE THEM SAME EVENT_ID
            for res in result:
                ps_cur.execute("SELECT event_id FROM events ORDER BY id;")
                all_event_ids = ps_cur.fetchall()
                if len(all_event_ids) > 0:
                    max_event_id = max(all_event_ids[:])
                    event_id = max_event_id[0] + 1
                else:
                    event_id = 1

                ps_cur.execute("SELECT event_id FROM events WHERE (device_reg_id = %s) ORDER BY id;", (feat_len + 1,))
                dev_event_ids = ps_cur.fetchall()
                ps_cur.execute("SELECT packets_transmitted FROM events WHERE (device_reg_id=%s) ORDER BY id;", (feat_len + 1,))
                dev_packs_transmitted = ps_cur.fetchall()
                ps_cur.execute("SELECT start_timestamp FROM events WHERE (device_reg_id=%s) ORDER BY id;", (feat_len + 1,))
                dev_start_timestamps = ps_cur.fetchall()
                ps_cur.execute("SELECT end_timestamp FROM events WHERE (device_reg_id=%s) ORDER BY id;", (feat_len + 1,))
                dev_end_timestamps = ps_cur.fetchall()

                for dei, dpt, dst, det in zip (dev_event_ids, dev_packs_transmitted, dev_start_timestamps, dev_end_timestamps):
                    if int(res[0]) == int(dpt[0]):
                        if abs(float(res[2]) - float(res[1]) - (float(det[0])- float(dst[0]))) < 1:
                            event_id = dei
                            break

                ps_cur.execute("INSERT INTO events (device_reg_id, packets_transmitted, start_timestamp, end_timestamp, event_id) VALUES (%s, %s, %s, %s, %s);",
                                (feat_len + 1, res[0], res[1], res[2], event_id))
                conn.commit()
                
            ps_cur.execute("SELECT event_id, avg(packets_transmitted), avg(end_timestamp - start_timestamp) FROM events WHERE (device_reg_id = %s) GROUP BY event_id;", (feat_len + 1,))
            result = ps_cur.fetchall()
            DBC(self.name, self.user, self.password, self.host, self.port).disconnect(conn)

            #append the statistics of this device
            features.append(self.CR_statistics(stat_table, result, current_time, last_time))
            feat_len += 1
        return(features)

    def CR_statistics(self, stat_table, result, current_time, last_time):
        if len(result) > 0:
            result = np.asarray(result)
            result[:,1] = result[:,1].astype(float)
            stat_table[0] = min(result[:,1])
            stat_table[1] = max(result[:,1])
            stat_table[2] = np.percentile(result[:,1], 25)
            stat_table[3] = np.percentile(result[:,1], 50)
            stat_table[4] = np.mean(result[:,1])
            stat_table[5] = np.percentile(result[:,1], 75)
            stat_table[6] = np.std(result[:,1])
            stat_table[7] = stat_table[5] - stat_table[2]
            stat_table[8] = min(result[:,2])
            stat_table[9] = max(result[:,2])
            stat_table[10] = np.percentile(result[:,2], 25)
            stat_table[11] = np.percentile(result[:,2], 50)
            stat_table[12] = np.mean(result[:,2])
            stat_table[13] = np.percentile(result[:,2], 75)
            stat_table[14] = np.std(result[:,2])
            stat_table[15] = stat_table[5] - stat_table[2]
            stat_table[16] = float(len(result[:,1]))
        return(stat_table)

         
    def CR_CE_execution(self, features, ip_devices, bt_devices, zw_devices, rf_devices, zb_devices, current_time, last_time):

        #call the CR events extraction functions for the three protocols
        features = self.CR_events_IP(current_time, last_time, features, ip_devices)
        features = self.CR_events_BT_ZW_RF_ZB(current_time, last_time, features, bt_devices, "bt")
        features = self.CR_events_BT_ZW_RF_ZB(current_time, last_time, features, zw_devices, "zw")
        features = self.CR_events_BT_ZW_RF_ZB(current_time, last_time, features, rf_devices, "rf")
        features = self.CR_events_BT_ZW_RF_ZB(current_time, last_time, features, zb_devices, "zb")

        return(features)