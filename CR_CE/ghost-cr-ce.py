import logging
import logging.handlers
import argparse
import signal
import sys, os
import time, datetime
from ghost_cr_ce.FINAL_FEATURES import FF
from ghost_cr_ce.DATABASE_COMMUNICATION import DBC
from ghost_cr_ce import CR_CE_REQUEST_ADDRESS
sys.path.append(os.path.relpath(os.path.join('../communication_protocols/python')))
from ghost_protocol.communicator import Communicator
from ghost_protocol.utils import get_configuration
from ghost_protocol.cr_ce_pb2 import ReducedData, CR_CE_Devices, DataForContextReasoning, FullData

# CR_CE version number
__version__ = "0.10"

LOG_VALUES = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "notset": logging.NOTSET
}

class CR_CE:
    #initialization of the class
    def __init__(self, config):
        self._communicator = Communicator(CR_CE_REQUEST_ADDRESS, self._on_request, None, [], [])
        self.config = config
        self._db_name = config.get("Database", "name")
        self._db_user = config.get("Database", "user")
        self._db_password = config.get("Database", "password")
        self._db_host = config.get("Database", "host")
        self._db_port = config.get("Database", "port")
        self.short_interval = config.get("Time", "short_interval")
        self.long_interval = config.get("Time", "long_interval")
        self.training_period = config.get("Time", "training_period")
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
    
    @staticmethod
    def _on_request(request):
        cr_ce_devices = CR_CE_Devices()
        cr_ce_devices.ParseFromString(request.data)
        if request.name.startswith("training"):
            logging.info("Receiving request from training")
            #the current time
            current_time = float(cr_ce_devices.timestamp)
            #the last time is the current time minus the duration of the training period 
            last_time = current_time - int(cr_ce.training_period)  
            if request.name == "training_short":
                #connect to the database
                ps_cur, conn = DBC(cr_ce._db_name, cr_ce._db_user, cr_ce._db_password, cr_ce._db_host, cr_ce._db_port).connect()
                ps_cur.execute("TRUNCATE TABLE cr_ce_parameters RESTART IDENTITY;")
                #disconnect from the database
                DBC(cr_ce._db_name, cr_ce._db_user, cr_ce._db_password, cr_ce._db_host, cr_ce._db_port).disconnect(conn)
                red_data, instances_total_data = FF(cr_ce.config).training_final_features(cr_ce_devices.ip_devices.ip, cr_ce_devices.bt_devices.bt, cr_ce_devices.zw_devices.zw, 
                                                    cr_ce_devices.rf_devices.rf, cr_ce_devices.zb_devices.zb, current_time, last_time, int(cr_ce.short_interval), "short")
            else:
                red_data, instances_total_data = FF(cr_ce.config).training_final_features(cr_ce_devices.ip_devices.ip, cr_ce_devices.bt_devices.bt, cr_ce_devices.zw_devices.zw, 
                                                    cr_ce_devices.rf_devices.rf, cr_ce_devices.zb_devices.zb, current_time, last_time, int(cr_ce.long_interval), "long")
            full_data = FullData()
            #fill the proto message with the red_data
            for i, rd, in enumerate(red_data):
                full_data.reduced_data.device_data.add()
                for vl in rd:
                    full_data.reduced_data.device_data[i].value.append(vl)
            #fill the proto message with the training_data
            for i, itd in enumerate(instances_total_data):
                full_data.training_data.add()
                for j, rd, in enumerate(itd):
                    full_data.training_data[i].device_data.add()
                    for vl in rd:
                        full_data.training_data[i].device_data[j].value.append(vl)
            request.reply(full_data.SerializeToString())
            
        elif request.name.startswith("running"):
            logging.info("Receiving request from running")
            #the current time
            current_time = time.time()
            if request.name == "running_short":
                #the last time is a short time interval before the current time
                last_time = current_time - int(cr_ce.short_interval)
                red_data = FF(cr_ce.config).running_final_features(cr_ce_devices.ip_devices.ip, cr_ce_devices.bt_devices.bt, cr_ce_devices.zw_devices.zw, 
                                                       cr_ce_devices.rf_devices.rf, cr_ce_devices.zb_devices.zb, current_time, last_time, int(cr_ce.short_interval), "short")
            else:
                #the last time is a long time interval before the current time
                last_time = current_time - int(cr_ce.long_interval)
                red_data = FF(cr_ce.config).running_final_features(cr_ce_devices.ip_devices.ip, cr_ce_devices.bt_devices.bt, cr_ce_devices.zw_devices.zw, 
                                                       cr_ce_devices.rf_devices.rf, cr_ce_devices.zb_devices.zb, current_time, last_time, int(cr_ce.long_interval), "long")
            reduced_data = ReducedData()
            #fill the proto message with the red_data
            for i, rd, in enumerate(red_data):
                reduced_data.device_data.add()
                for vl in rd:
                    reduced_data.device_data[i].value.append(vl)
            request.reply(reduced_data.SerializeToString())
        else:
            logging.info("Receiving request from context reasoning")
            data_for_context_reasoning = DataForContextReasoning()
            data_for_context_reasoning.ParseFromString(request.data)
            template_data = []
            new_data = []
            for (td,nd) in zip(data_for_context_reasoning.template_data.value, data_for_context_reasoning.new_data.value):
                template_data.append(td)
                new_data.append(nd)
            if request.name == "context_short":
                reason = FF(cr_ce.config).get_context(template_data, new_data, "short")
            else:
                reason = FF(cr_ce.config).get_context(template_data, new_data, "long")
            request.reply(reason)

    def stop(self):
        self._communicator.stop()
        self.runner = False

def signal_handler(signum, frame):
    """Signal handler which stops the CR_CE module upon reception of a signal."""
    logging.info('Signal received: stopping...')
    cr_ce.stop()
    logging.shutdown()

if __name__ == "__main__":
    logging.info("Reading command line arguments.")
    sys.path.append(os.getcwd())
    

    parser = argparse.ArgumentParser(description="The CR_CE module.")
    parser.add_argument(
        "--version", help="display the version",
        action="version", version="%(prog)s {}".format(__version__))
    parser.add_argument(
        "--config", "-c",
        help="the path and name of the configuration file",
        required=True)
    args = parser.parse_args()
    config = get_configuration(args.config)

    cr_ce = CR_CE(config)
    
    if sys.platform.startswith('linux'):
        signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    while cr_ce.runner:
        try:
            time.sleep(1)
        except Exception:
            pass
        