from ghost_protocol.base_pb2 import ReplyHeader


class Request:
    """
    Encapsulation of a request which have a name and an optional data.
    Used to send the reply to a request.
    Do not directly instantiate this class.
    """

    def __init__(self, peer_id, request_header, data):
        self._peer_id = peer_id
        self._request_header = request_header
        self.data = data

    @property
    def name(self):
        return self._request_header.name

    def reply(self, data):
        raise NotImplementedError

    def _make_reply(self, data):
        reply_header = ReplyHeader()
        reply_header.id = self._request_header.id
        reply = [self._peer_id, reply_header.SerializeToString()]
        reply.append(bytes() if not data else data)
        return reply
