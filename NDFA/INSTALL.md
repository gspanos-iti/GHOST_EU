
## Dependencies

The NDFA has the following direct dependencies:
* **libprotoident** Network traffic classification library.
* **tshark** The Wireshark Network Analyzer
* **wireshark-common** or **wireshark-cli** Network traffic analyzer.
* **pyshark** Python wrapper for tshark,
* **dpkt** fast, simple packet creation / parsing
* **timeout-decorator** Timeout decorator for Python.
* **psycopg2** PostgreSQL database adapter for Python
* **daemon** Python daemonizer for Unix, Linux and OS X
* **lockfile** Platform-independent file locking.

# Install prerequisites

## Debian systems

### Install tshark and python libraries
```console
apt-get install tshark python-pip
pip install psycopg2 pyshark timeout-decorator dpkt
```

### Install libprotoident library
```console
apt-get install apt-transport-https
echo "deb https://packages.wand.net.nz $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/wand.list
curl https://packages.wand.net.nz/keyring.gpg -o   /etc/apt/trusted.gpg.d/wand.gpg
apt-get update
apt-get install libprotoident
```

## Non-Debian systems

### Install tshark

Make sure tshark is installed

### Install python libraries

Install python libraries of the following list
* **pyshark** Python wrapper for tshark (https://github.com/KimiNewt/pyshark)
* **dpkt** fast, simple packet creation / parsing (https://github.com/kbandla/dpkt)
* **timeout-decorator** Timeout decorator for Python (https://github.com/pnpnpn/timeout-decorator)
* **psycopg2** PostgreSQL database adapter for Python (https://github.com/psycopg/psycopg2)
* **daemon** Python daemonizer for Unix, Linux and OS X (https://github.com/serverdensity/python-daemon)
* **lockfile** Platform-independent file locking (https://pypi.org/project/lockfile/0.12.2/#files)

### Install libprotoident

Install libprotoident as it is described in https://github.com/wanduow/libprotoident

### Install libprotoident library on Raspberry PI

```console
cd /tmp
git clone https://github.com/wanduow/libprotoident
wget https://research.wand.net.nz/software/libtrace/libtrace-latest.tar.bz2
wget https://research.wand.net.nz/software/wandio/wandio-1.0.4.tar.gz
wget https://research.wand.net.nz/software/libflowmanager/libflowmanager-3.0.0.tar.gz
tar -xvzf ./wandio-1.0.4.tar.gz
cd wandio-1.0.4
./configure
make
make install
cd ..
tar -xvjf ./libtrace-latest.tar.bz2
cd libtrace-4.0.3
./configure
make
make install
cd ..
tar -xvzf ./libflowmanager-3.0.0.tar.gz
cd libflowmanager-3.0.0
./configure
make
make install
cd ..
cd libprotoident
./bootstrap.sh
./configure
make
make install
cd ..
rm -f -R ./libprotoident
rm -f -R ./wandio-1.0.4/
rm -f -R ./libtrace-4.0.3/
rm -f -R ./libflowmanager-3.0.0/
rm -f ./libtrace-latest.tar.bz2
rm -f ./wandio-1.0.4.tar.gz
rm -f ./libflowmanager-3.0.0.tar.gz
```