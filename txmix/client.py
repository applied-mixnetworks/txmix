
from __future__ import print_function


class Client(object):

    def __init__(self, pki, transport, encoding):
        self.pki = pki
        self.transport = transport
        self.encoding = encoding

    def send(self, node_id, message):
        addr = self.pki.getAddr(self.transport.name, node_id)
        serialized_message = self.encoding.serialize(message)
        self.transport.send(addr, serialized_message)
