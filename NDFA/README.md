# Directory structure

* In the root directory of NDFA component the main file that has to be executed is **ghost_ndfa.py**.
* The configuration file is given as an argument **--config** when executing the main script. A template for the configuration file exists in root directory and is named **config.template.ini**.
* Adittionally there is a directory **ghost_ndfa** which contains one python file for each different interface processor used. Currently there are two file in this directory namely **ip_packets_processor.py** and **bt_packets_processor.py**.
* There are two auxilliary files **setup.py** in root directory and **__init.py__** in the ghost_ndfa directory.


# Running NDFA component

## Database
A PostgreSQL database installation is needed for storing the data output. The details and credentials for database access are included in config file.

## Capturing traffic
You should first start the traffic capturing by using tshark. The following command deletes old pcpa files from previous executions and starts tshark

**rm -f [path_of_pcap_files]/* & tshark -i [interface] -b duration:[pcap_files_duration] -b files:[pcap_files_number] -w [path_of_pcap_files]/[file_name].pcap**

You have to edit the parameters of the command according to your setup

* **[path_of_pcap_files]** is the absolute or relative path where the pcap files are going to be stored
* **[interface]** is the name of the interface to be captured
* **[pcap_files_duration]** is the time duration of each pcap file
* **[pcap_files_number]** is the maximum number of pcap files maintained in the directory
* **[file_name]** is a name used for the captured files (can be any filename)

For example the script :

**rm -f pcap_files/* & tshark -i eth0 -b duration:10 -b files:100 -w pcap_files/10sec_capture.pcap**

captures at most **100 files** from **interface eth0** each one of which lasts **10 secs** and stores those to **directory pcap_files**.

## Executing the main script

Then you have to execute the main ndfa component by using the command

**python  ghost-ndfa.py -c config.template.ini**

# Testing NDFA component

## Preparing tests

Download pcaps.tar.gz file from https://colabora.televes.com/products/files/#657
Untar this file in root NDFA directory. After that there should exist 6 directories ip_short, bt_short, zwave_short, rf_short, ppp_short, zigbee_short in directory GHOST/NDFA/pcaps/.

## Running the tests

Run the four tests exisiting in GHOST/NDFA/tests/ directory:

**python  test_ip_processor.py**
**python  test_bt_processor.py**
**python  test_zw_processor.py**
**python  test_rf_processor.py**
**python  test_ppp_processor.py**
**python  test_zb_processor.py**


