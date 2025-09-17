# Readme

Communication protocol and libraries for communication between GHOST modules using [ZeroMQ](http://zeromq.org/)
and [Protocol Buffers](https://developers.google.com/protocol-buffers/).

The directory contains the following:
* `doc` - documentation describing the communication protocol.
Includes the actual documentation file (`CommunicationProtocols.adoc` using AsciiDoc format) and used drawings
(*.dia the source of drawings and *.svg the generated drawings using SVG format.)
* `c` - the C implementation of the communication library
* `java` - the Java implementation of the communication library
* `python` - the Python implementation of the communication library
* `proto/ghost/*.proto` - files describing Protocol Buffer structures used for communication:
  * `base.proto` - base data structures used for communication patterns
  * `inter.proto` - data structures used for Interoperability Interface (communication between GHOST and Gateway)
  * `cladf.proto` - data structures used for comunication with CLADF module
* `generate.sh` - script to generate source code from `*.proto` files.
Must be called before building or using the library implementations.

