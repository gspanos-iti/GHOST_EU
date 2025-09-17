# Readme

GHOST communication library for Python.

## Directory structure

The library contains the following file structure:
* `./ghost` - library files, including communicator.py containing the main communication class
* `./test/demo` - containing test/demo scripts
* `./test/unit` - containing the unit test

## Running the unit tests

To run the unit tests run the following command:

python -m unittest discover

## Using the library

The main class of the library is the **Communicator**, used for communication with other GHOST modules.
A communicator can:
* send requests to other modules
* reply to incoming requests from other modules
* publish data on a topic to subscribed modules
* receive notification from other modules when data is published on a topic.

Examples of it's usage are provided in the *mockup_gateway.py* and *mockup_module.py* scripts.
The *mockup_gateway.py* is simulating the gateway software which is using a **Communicator** object to communicate with one or more GHOST modules.
The *mockup_module.py* is simulating a GHOST module which is using a **Communicator** object to communicate with gateway software to obtain various information (e.g. device list, captured packets, etc.)

The following exemplifies the skeleton of a Python module using the **Communicator** to communicate with other module.

```python
from ghost.communicator import Communicator

# ZeroMQ address - using ipc (UNIX domain sockets) addresses; modules on the same machine
# address for incomming request to this module
REQUEST_ADDRESS = "ipc://tmp/my_module_request"
# address to publish notfication from this module
PUBSUB_ADDRESS = "ipc://tmp/my_module_pubsub"
# address where to send requests to the other module
OTHER_MODULE_REQUEST_ADDRESS = "ipc://tmp/other_module_request"
# address where to subscribe for notifications from the other module
OTHER_MODULE_PUBSUB_ADDRESS = "ipc://tmp/other_module_pubsub"


def on_request(request):
    """Called when a request was received"""

    # do some processing

    # send back the reply
    request.reply(...)

def on_topic(name, data):
    """Called when a notification was received"""
    # process the notification

def on_reply(data):
    """
    Called when the reply to 'some_request' sent to
    the 'other_module' is received.
    """
    # process the reply

# construct the communicator
communicator = Communicator(
            REQUEST_ADDRESS,
            on_request,
            PUBSUB_ADDRESS,

            # prepare for requests to the other module
            [("other_module", OTHER_MODULE_REQUEST_ADDRESS)],

            # subscribe to the other module for 'some_topic'
            [Communicator.Subscription(
                OTHER_MODULE_PUBSUB_ADDRESS,
                ["some_topic"], on_notification)])
# ...

# send 'some_request' to the other module
communicator.request("other_module", "some_request", request_data, on_reply)

# ...

# dispatch a notification on 'my_topic'
communicator.publish("my_topic", topic_data)

# ...

# stop the communicator
communicator.stop()

```