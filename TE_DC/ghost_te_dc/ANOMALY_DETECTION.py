from scipy.spatial import distance
import logging
import time, sys, os, math
sys.path.append(os.path.relpath(os.path.join('../communication_protocols/python')))
from ghost_protocol.te_dc_pb2 import AnomalyDetection
from ghost_protocol.cr_ce_pb2 import DataForContextReasoning
sys.path.append(os.path.relpath(os.path.join('..')))
from ghost_te_dc import TE_DC_PUBSUB_ADDRESS, TE_DC_ALERT_TOPIC


class AD:
    _message = None
    #GET DEVICES
    def anomaly_detection(self, c, new_data, clusters, templates, all_devices, distances, duration):
        for i, (nd, ad) in enumerate(zip(new_data, all_devices)):
            alert = AnomalyDetection()
            alert.timestamp = str(time.time())
            alert.device.id.value = ad[0]
            if ad[1]:
                alert.device.bluetooth.mac_address = ad[1]
            if ad[2]:
                alert.device.description = ad[2]
            if ad[3]:
                alert.device.type = int(ad[3])
            if ad[4]:
                alert.device.ip4.address = ad[4]
            if ad[5]:
                alert.device.rf869.address = ad[5]
            if ad[6]:
                alert.device.zigbee.mac_address = ad[6]
            if ad[7]:
                alert.device.zwave.home_id = ad[7]
            if ad[8]:
                alert.device.zwave.node_id = ad[8]
            #check for changes in the devices according to the distance from their templates
            if distance.minkowski(nd, templates[clusters[i]], p = 2) > distances[clusters[i]]:
                self._request_context(nd, templates[clusters[i]], c, duration)
                score = distances[clusters[i]] / distance.minkowski(nd, templates[clusters[i]], p = 2)
                alert.severity_score = int(math.ceil((1 - score) * 10))
                alert.reliability_score = alert.severity_score
                alert.reason = AD._message
            else:
                alert.severity_score = 0
                if distances[clusters[i]] > 9:
                    alert.reliability_score = 0
                else:
                    alert.reliability_score = int(math.floor(10 - distances[clusters[i]]))
                alert.reason = "Normal Behavior"
            c.publish(TE_DC_ALERT_TOPIC, alert.SerializeToString())
            logging.debug("Alert was published [" + TE_DC_ALERT_TOPIC + "," + TE_DC_PUBSUB_ADDRESS + "]")
            logging.debug(alert)


    def _request_context (self, new_data, templates, c, duration):
        data_for_context_reasoninig = DataForContextReasoning()
        for (nd, tmp) in zip(new_data, templates):
            data_for_context_reasoninig.new_data.value.append(nd)
            data_for_context_reasoninig.template_data.value.append(tmp)
        AD._message = None
        c.request("cr_ce", "context_" + duration, data_for_context_reasoninig.SerializeToString(), self._on_reply_context, timeout = 300)
        while not AD._message:
            try:
                time.sleep(1)
            except Exception:
                pass   

    @staticmethod
    def _on_reply_context(data): 
        AD._message = data
