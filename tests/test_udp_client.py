# -*- coding: utf-8 -*-

from zope.interface import implementer
from twisted.internet import reactor
from twisted.internet.interfaces import IReactorCore

from sphinxmixcrypto import SphinxParams, GroupECC, Chacha_Lioness, Chacha20_stream_cipher, Blake2_hash
from sphinxmixcrypto import generate_node_keypair, generate_node_id_name

from txmix import UDPClient, IPKIClient, NodeDescriptor, CBOREncodingHandler, IMixClientTransport


class NodeTransportMismatchError(Exception):
    """
    """

@implementer(IMixClientTransport)
class DummyClientTransport(object):

    name = "dummy"

    def __init__(self, received_callback):
        self.received_callback = received_callback
        self.receive = []
        self.sent = []

    def received(self, message):
        self.receive.append(message)
        self.received_callback(message)

    def send(self, addr, message):
        self.sent.append(message)

@implementer(IPKIClient)
class FakePKI():
    consensus = None

    def __init__(self, consensus):
        self.consensus = consensus

    def get_consensus(self):
        return self.consensus

    def register(self, mix_descriptor):
        pass

    def getAddr(self, transport_name, node_id):
        node_descriptor = self.consensus[node_id]
        if node_descriptor.transport_name != transport_name:
            print("%s != %s" % (node_descriptor.transport_name, transport_name))
            raise NodeTransportMismatchError
        return node_descriptor.addr

@implementer(IReactorCore)
class FakeReactor:

    def listenUDP(self, port, transport, interface=None):
        pass


def test_UDPClient():
    hops = 5
    params = SphinxParams(
            hops, group_class = GroupECC,
            hash_func = Blake2_hash,
            lioness_class = Chacha_Lioness,
            stream_cipher = Chacha20_stream_cipher,
    )
    received = []
    consensus = {}
    for i in range(2*hops):
        public_key, private_key = generate_node_keypair(params.group)
        node_id, node_name = generate_node_id_name(params.k)
        addr = ('127.0.0.1', 1234) # XXX fix me
        node_descriptor = NodeDescriptor(node_id, public_key, "dummy", addr)
        consensus[node_descriptor.id] = node_descriptor
    pki = FakePKI(consensus)
    encoding_handler = CBOREncodingHandler()
    def received_callback(message):
        received.append(message)
    fakeReactor = FakeReactor()
    client = UDPClient(fakeReactor, '127.0.0.1', 2020, received_callback, params, pki, encoding_handler)
    dummy_transport = DummyClientTransport(client.received)
    client.transport = dummy_transport
    client.start()

    # test send
    dest = pki.get_consensus().keys()[0]
    client.send(dest, b"hurray for mixnets!")
    assert len(dummy_transport.sent) == 1
    assert len(dummy_transport.sent[0]) == 1271
