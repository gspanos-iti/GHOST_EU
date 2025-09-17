import logging
import unittest
import zmq

from ghost_protocol.request import Request
from ghost_protocol.requestor import Requestor
from ghost_protocol.timeouts import Timeouts
from ghost_protocol.base_pb2 import RequestHeader


class Responder(object):

    def __init__(self, address):
        self._socket = zmq.Context.instance().socket(zmq.ROUTER)
        self._socket.bind(address)

    def close(self):
        self._socket.close()

    def recv(self):
        message = self._socket.recv_multipart()

        length = len(message)

        if length not in [2, 3]:
            logging.warning("Invalid request length: %s!", length)
            return

        # extract peer id
        peer_id = message[0]

        # extract request
        request_header = RequestHeader()
        request_header.ParseFromString(message[1])

        # pylint: disable=E1101
        logging.debug("RECV: %s %s", request_header.id, request_header.name)
        # pylint: enable=E1101

        data = None
        if length == 3:
            data = message[2]

        self._request_handler(Request(peer_id, request_header, data))

    def _request_handler(self, request):
        self.close()

class RequestorHelper(Requestor):
    """
    Helper for working with Requestor.
    """
    def __init__(self, address, timeouts):
        Requestor.__init__(self, address, timeouts)

        self.request = self._request


class TestRequest(unittest.TestCase):
    """
    Test suite for Requestor.
    """

    def setUp(self):
        # Setup for the test case.
        self._address = "tcp://127.0.0.1:5555"

    def tearDown(self):
        # Here you can make the cleanup for the next test.
        pass

    # From here on define methods for every test case.

    def test_requestor_make_requetor(self):
        """
        Test case for sending a request.
        """

        # TODO: implement this
        # 1. Create responder
        # 2. Create requestor
        # 3. Wait for the request to be responded
        # 4. exit

        self._responder = Responder(self._address)
        self._timeouts = Timeouts()
        self._requestor = RequestorHelper(self._address, self._timeouts)

        self._requestor.request("intefaces.get", None, None, 30)

        self.assertEqual(1, 1)
