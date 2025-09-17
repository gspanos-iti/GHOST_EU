import unittest

from ghost_protocol.base_pb2 import RequestHeader
from ghost_protocol.request import Request


class TestRequest(unittest.TestCase):
    """
    Test suite for request.
    """

    def setUp(self):
        # Setup for the test case.
        self._peer_id = 123
        self._id = 123

    def tearDown(self):
        # Here you can make the cleanup for the next test.
        pass

    # From here on define methods for every test case.

    def test_request(self):
        """
        Test case for checking the setter/getter methods for a request.
        """

        request_header = RequestHeader()
        request_header.id = self._id
        request_header.name = "interfaces.get"

        request = Request(self._peer_id, request_header, None)
        self.assertEqual(request.name, "interfaces.get")

    def test_request_reply_not_implemented(self):
        """
        Test case for checking that the reply is not implemented.
        """
        request_header = RequestHeader()
        request_header.id = self._id
        request_header.name = "interfaces.get"

        request = Request(self._peer_id, request_header, None)
        self.assertRaises(NotImplementedError, request.reply, None)

    def test_request_make_reply(self):
        """
        Test case for the make_reply method.
        """
        # make make_reply accesible
        class RequestHelper(Request):
            def __init__(self, peer_id, request_header, data):
                Request.__init__(self, peer_id, request_header, data)

            def make_reply(self, data):
                return self._make_reply(data)

        request_header = RequestHeader()
        request_header.id = self._id
        request_header.name = "interfaces.get"

        request = RequestHelper(self._peer_id, request_header, None)

        reply = request.make_reply(None)
        self.assertIsInstance(reply, list)
        self.assertEqual(len(reply), 3)
        self.assertEqual(reply[0], self._peer_id)

        self.assertIs(type(reply[1]), str)
        self.assertIs(type(reply[2]), str)
