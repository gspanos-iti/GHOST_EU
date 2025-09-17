from collections import deque
import sys
import zmq

from ghost_protocol.base_pb2 import RequestHeader
from ghost_protocol.request import Request
from ghost_protocol.requestor import Requestor
from ghost_protocol.timeouts import Timeouts

from threading import Thread
if sys.version_info >= (3, 0):
    from threading import get_ident
else:
    from thread import get_ident


class Communicator(Thread):
    """
    Main class used for communication with other modules.

    Use request method to send requests to other modules.
    Use publish method to dispatch notifications to other modules.
    """

    _CONTROL_ADDRESS = "inproc://control"
    _STOP_MESSAGE = b"stop"  # used to signal the event loop to stop
    _POST_MESSAGE = b"post"  # use to signal a new handler was posted
    _HANDLERS_LIMIT = 100  # maximum number of handlers to call at once
    _DEFAULT_TIMEOUT = 60  # 60 seconds

    class Subscription:
        """Encapsulate subscription information."""

        def __init__(self, address, topics, handler):
            """
            Parameters:
              address - string - the ZeroMQ address
              topics - set of strings - the topics to subscribe to
              handler - function to be called when a notification is received.
                The function is called from the communicator thread and it
                should not be blocked.
                Takes tow parameters:
                  topic - string - notification topic
                  data - bytes - the notification data
            """
            self.address = address
            self.topics = topics
            self.handler = handler

    def __init__(self,
                 request_address,
                 request_handler,
                 publish_address,
                 requestors,
                 subscriptions):
        """
        Parameters:
          request_address - ZeroMQ address for incoming requests.
          request_handler - function to be called when a request is received.
            Takes one parameter: the request of type Request.
            Use Request.reply to respond to the request.
          publish_address - string - ZeroMQ address used to publish
            notifications.
          requestors - list of tuples specifying the requestors to other
            modules.
            Each tuple contain two strings: module name and ZeroMQ address).
          subscriptions - list of Subscription
        """
        Thread.__init__(self)

        self._context = zmq.Context.instance()

        self._poller = zmq.Poller()

        # list of posted handlers to be called inside the Communicator thread.
        self._handlers = deque()

        # sockets used for loop control
        self._control_pull = self._context.socket(zmq.PULL)
        self._control_pull.bind(self._CONTROL_ADDRESS)
        self._poller.register(self._control_pull, zmq.POLLIN)
        self._control_push = self._context.socket(zmq.PUSH)
        self._control_push.connect(self._CONTROL_ADDRESS)

        self._replier = None
        self._request_handler = request_handler
        self._publisher = None

        self._timeouts = Timeouts()

        # setup socket for incoming requests
        if request_address:
            self._replier = self._context.socket(zmq.ROUTER)
            self._replier.setsockopt(zmq.LINGER, 0)
            self._replier.bind(request_address)
            self._poller.register(self._replier, zmq.POLLIN)

        # setup socket for publishing notifications
        if publish_address:
            self._publisher = self._context.socket(zmq.PUB)
            self._publisher.bind(publish_address)

        # initialize request sockets
        # map between module name and requestor
        self._requestors_module = dict()
        # map between socket and requestor
        self._requestors_socket = dict()
        for info in requestors:
            requestor = Requestor(info[1], self._timeouts)
            self._requestors_module[info[0]] = requestor
            self._requestors_socket[requestor._socket] = requestor
            self._poller.register(requestor._socket, zmq.POLLIN)

        # initialize subscriptions sockets
        self._subscriptions = dict()
        for subscription in subscriptions:
            socket = self._context.socket(zmq.SUB)
            socket.connect(subscription.address)
            for topic in subscription.topics:
                if sys.version_info >= (3, 0):
                    socket.setsockopt(zmq.SUBSCRIBE, bytes(topic, "utf-8"))
                else:
                    socket.setsockopt(zmq.SUBSCRIBE, topic)
            self._poller.register(socket, zmq.POLLIN)
            self._subscriptions[socket] = subscription.handler

        # start the event thread
        self.start()

    def request(self, module, name, data, handler, timeout=_DEFAULT_TIMEOUT):
        """
        Make a request to a module.
        There MUST be a requestor specified for the required module when
        Communicator is instantiated.
        The function is thread safe.

        Parameters:
          module - string - module name
          name - string - request name
          data - bytes or None - request data
          handler - function to be called when the reply is received.
            The function takes one parameter: the response data.
            The function will be called by the Communicator thread.
          timeout - in seconds to wait for reply.
            If reply is not received in the specified time the handler will be
            called with None.
        """
        # if from outside thread then use post
        if get_ident() != self.ident:
            self.post(
                lambda: self.request(module, name, data, handler, timeout))
            return

        requestor = self._requestors_module[module]
        requestor._request(name, data, handler, timeout)

    def publish(self, topic, data):
        """
        Publish a notification.
        Other modules must be subscribed to the topic in order to receive
        these notifications.
        The function is thread safe.

        Parameters:
          topic - string - notification topic
          data - bytes - notification data
        """

        # if from outside thread then use post
        if get_ident() != self.ident:
            self.post(
                lambda: self.publish(topic, data))
            return

        if sys.version_info >= (3, 0):
            message = [bytes(topic, "utf-8")]
        else:
            message = [topic.encode('utf8')]
        if data:
            message.append(data)
        self._publisher.send_multipart(message)

    def post(self, handler):
        """
        Deffer the call of a function to the Communicator thread.
        """
        self._handlers.append(handler)
        # if post is made from another thread then also signal the thread to
        # wake up
        if get_ident() != self.ident:
            self._control_push.send(self._POST_MESSAGE)

    def stop(self):
        """
        Stop the communicator.
        Close all sockets and terminate the thread.
        """

        # signal and wait for the thread to terminate
        self._control_push.send(self._STOP_MESSAGE)
        self.join()

        # close all sockets
        if self._replier:
            self._replier.close()
        if self._publisher:
            self._publisher.close()
        for requestor in self._requestors_module.values():
            requestor._close()
        for subscriber in self._subscriptions:
            subscriber.close()

    def run(self):
        """Event loop for handling incoming messages"""

        running = True
        while running:
            wait_time = 0 if self._handlers else self._timeouts.get_wait()
            events = self._poller.poll(wait_time)

            for event in events:
                if event[0] == self._replier:
                    self._on_request()
                elif event[0] == self._control_pull:
                    message = self._control_pull.recv()
                    if message == self._STOP_MESSAGE:
                        # stop received
                        running = False
                        break
                    elif message == self._POST_MESSAGE:
                        # handlers will be processed outside the for
                        pass
                else:
                    requestor = self._requestors_socket.get(event[0])
                    if requestor:
                        requestor._on_message()
                        continue

                    handler = self._subscriptions.get(event[0])
                    if handler:
                        self._on_notification(event[0], handler)

            self._timeouts.process()
            self._process_handlers()

    def _process_handlers(self):
        count = 0
        while count < self._HANDLERS_LIMIT and len(self._handlers):
            handler = self._handlers.popleft()
            handler()
            count += 1

    def _on_request(self):

        message = self._replier.recv_multipart()

        length = len(message)
        if length < 2:
            return

        peer_id = message[0]

        request_header = RequestHeader()
        request_header.ParseFromString(message[1])

        request = Request(peer_id, request_header,
                          message[2] if length > 2 else None)
        request.reply = lambda data: self._reply(request, data)

        self._request_handler(request)

    def _reply(self, request, data):
        # if from outside thread then use post
        self._replier.send_multipart(request._make_reply(data))

    def _on_notification(self, socket, handler):
        topic, data = self._extract(socket.recv_multipart())
        handler(topic, data)

    @staticmethod
    def _extract(message):
        string = message[0].decode('utf8')
        binary = None
        if len(message) > 1:
            binary = message[1]
        return (string, binary)
