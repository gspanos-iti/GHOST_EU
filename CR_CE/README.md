This module is used for identifying the communication events that are related with each device and also to compute packet-level metrics. More specifically, CR-CE takes its input by the NDFA's "ipv4_flows", "ipv4_packets", "bt_batches", "bt_packets", "zw_batches", "zw_packets", "rf869_flows", "rf869_packets", SQL tables. Its output is stored in "features", "events" and "cr_ce_parameters" SQL tables.

------------------------------------------------------------------------
SQL TABLES (OWNER:context_reasoning):

CREATE TABLE IF NOT EXISTS features (id SERIAL PRIMARY KEY,feature JSON  NOT NULL,device  INT);

CREATE TABLE IF NOT EXISTS events (id SERIAL PRIMARY KEY, device_reg_id INT, packets_transmitted INT,start_timestamp FLOAT,end_timestamp FLOAT,event_id INT);

CREATE TABLE IF NOT EXISTS cr_ce_parameters (name VARCHAR, value VARCHAR);

-----------------------------------------------------

STARTING THE MODULE: 

In order to run the module, a database installation should exist and the NDFA should be active also, so that the tables are not empty (at least one of the NDFA's tables should contain data). Moreover, device_info table should contain the smart home devices information. 

In CR_CE execute: python ghost-cr-ce.py -c cr_ce.ini

-----------------------------------------------------

TESTING THE MODULE: 

In order to test the module, load to the database the backup files that exist in unit_testing/data

In CR_CE execute: python unit_testing/test_ghost_cr_ce.py 


