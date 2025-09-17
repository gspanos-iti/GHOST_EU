import zmq

from ghost_protocol.base_pb2 import ReplyHeader, RequestHeader
from ghost_protocol.timeouts import get_timestamp


class Requestor:
    """
    Used to make requests.
    Do not directly instantiate this class.
    """

    def __init__(self, address, timeouts):
        self._id = 0
        self._requests = dict()
        self._timeouts = timeouts

        self._socket = zmq.Context.instance().socket(zmq.DEALER)
        self._socket.setsockopt(zmq.LINGER, 0)
        self._socket.connect(address)

    def _request(self, name, data, reply_handler, timeout):
        self._id += 1

        request_header = RequestHeader()
        request_header.id = self._id
        request_header.name = name

        if reply_handler:
            # only if we have a reply handler we add a timeout
            timeout_handler = lambda: self._on_timeout(request_header.id)
            timeout_timestamp = get_timestamp() + timeout
            self._requests[self._id] = (
                reply_handler, timeout_timestamp, timeout_handler)
            self._timeouts.add(timeout_timestamp, timeout_handler)

        message = [request_header.SerializeToString()]
        if data:
            message.append(data)
        self._socket.send_multipart(message)

    def _on_message(self):
        message = self._socket.recv_multipart()

        length = len(message)
        if length < 1:
            return

        reply_header = ReplyHeader()
        reply_header.ParseFromString(message[0])

        item = self._requests.pop(reply_header.id, None)
        if item:
            # on emtpy result use True as response data
            item[0](message[1] if length > 1 else True)
            # remove the timeout
            self._timeouts.remove(item[1], item[2])

    def _on_timeout(self, request_id):
        reply_handler, _, _ = self._requests.pop(request_id, None)
        # on timeout use None as response data
        reply_handler(None)

    def _close(self):
        self._socket.close()
        # remove all timeouts
        for request_id, request_info in self._requests.items():
            self._timeouts.remove(request_info[1], request_info[2])
