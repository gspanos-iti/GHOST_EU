TE-DC is used for creating templates which describe the behaviour of IoT devices. It takes its input from NDFA, CR and DC modules. Its output is stored in "templates" and "te_dc_parameters" SQL tables. Furthermore, at the running phase, the module detects anomaly behavior and sends notifications to RE according to the structure defined to the te_de.proto file in the communication_protocols. Finally, if a new device appeared,the module classifies the device into an existing template or creates a new template in order to classify the device.

-------------------------------------------------------

SQL TABLES (OWNER:template_extraction):

CREATE TABLE IF NOT EXISTS te_dc_parameters (name VARCHAR, value VARCHAR);

CREATE TABLE IF NOT EXISTS templates (id SERIAL PRIMARY KEY,template JSON  NOT NULL,devices  INT[]);

--------------------------------------------------------------------------

STARTING THE MODULE: 

In order to run the module, a database installation should exist, NDFA and CR_CE should be active and NDFA's tables should contain data (at least one of the NDFA tables: ipv4_packets, ipv4_flows, bt_packets, bt_batches etc). Moreover, device_info table should contain the smart home device information. If the training phase has already run and in order to ommit the training phase, change in _te_dc.ini_ the training_phase parameter from false to true.

In TE_DC execute: python ghost-te-dc.py -c te_dc.ini

--------------------------------------------------------------------------
TESTING THE COMMUNICATION WITH RE & CR_CE:

In order to test the module, load to the database the backup files that exist in testing/data

In te_dc.ini change the time parameters as follows:

- _"start"_ from 23:50 to the current time (plus 2-3 minutes)
- _"interval"_ from 60 to 10

In TE_DC open 3 different terminals & execute: 

1. python ghost-te-dc.py -c te_dc.ini 

2. python testing/mockup_re.py to check the communication wit RE

3. python testing/mockup_cr_ce.py -c testing/cr_ce.ini to check the communication wit CR_CE