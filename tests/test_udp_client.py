# -*- coding: utf-8 -*-

from zope.interface import implementer
from twisted.internet import reactor
from txmix import UDPClient, IPKIClient, IEncodingHandler



@implementer(IPKIClient)
class FakePKI():

    def __init__(self, consensus):
        self.consensus

    def get_consensus(self):
        return self.consensus

    def register(self, mix_descriptor):
        pass

    def getAddr(self, transport_handler, node_id):
        pass

@implementer(IEncodingHandler)
class FakeEncodingHandler():

    def serialize(message):
        return message

    def deserialize(message):
        return message


def test_udp_client():
    received = []
    def received_callback(message):
        received.append(message)

    self.node_map = {}
    for i in range(2*self.r):
        node_descriptor = NodeDescriptor()
        self.node_map[node_descriptor.get_id()] = node_descriptor

    pki = FakePKI(self.node_map)
    encoding_handler = FakeEncodingHandler()
    
    client = UDPClient(reactor, '127.0.0.1', 2020, received_callback, pki, encoding_handler)
    client.start()
