# -*- coding: utf-8 -*-

from zope.interface import implementer
from twisted.internet import reactor
from twisted.internet.interfaces import IReactorCore

from sphinxmixcrypto import SphinxParams, GroupECC, Chacha_Lioness, Chacha20_stream_cipher, Blake2_hash
from sphinxmixcrypto import generate_node_keypair, generate_node_id_name
from sphinxmixcrypto import rand_subset, SphinxClient, create_forward_message

from txmix import IPKIClient, NodeDescriptor, CBOREncodingHandler, IMixClientTransport, MixClientFactory



class NodeTransportMismatchError(Exception):
    """
    """

@implementer(IMixClientTransport)
class DummyClientTransport(object):

    name = "dummy"

    def __init__(self):
        self.received_callback = None
        self.receive = []
        self.sent = []
        self.client = None

    def start(self):
        pass

    def setClient(self, client):
        self.client = client

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

def build_mixnet(params):
    """
    build a mixnet and return a consensus dict
    node id -> node descriptor
    """
    mix_size = 40
    consensus = {}
    for i in range(mix_size):
        public_key, private_key = generate_node_keypair(params.group)
        node_id, node_name = generate_node_id_name(params.k)
        addr = ('127.0.0.1', 1234) # XXX fix me
        node_descriptor = NodeDescriptor(node_id, public_key, "dummy", addr)
        consensus[node_descriptor.id] = node_descriptor
    return consensus

def generate_route(params, pki, destination):
    """
    given a destination node ID a randomly chosen
    route is returned: a list of mix node IDs
    where the last element is the destination
    """
    return rand_subset(pki.get_consensus().keys(), params.r-1) + [destination]


class EchoClientProtocol(object):
    def setTransport(self, transport):
        self.transport = transport

    def messageReceived(self, message):
        if message.haskey('text'):
            if message['text'] == 'ping':
                print("ping received")
        print("non-ping received")
        # XXX send a reply ping
        #outgoing_message = {'message':'ping'}
        #self.transport.send(message['surb'], outgoing_message)


def test_EchoClient():
    """
    test for a simple mixnet echo client
    """

    client_received = []
    def received_callback(message):
        client_received.append(message)
    dummy_transport = DummyClientTransport()

    hops = 5
    params = SphinxParams(
        hops, group_class = GroupECC,
        hash_func = Blake2_hash,
        lioness_class = Chacha_Lioness,
        stream_cipher = Chacha20_stream_cipher,
    )
    consensus = build_mixnet(params)
    pki = FakePKI(consensus)

    fake_reactor = FakeReactor()
    client_factory = MixClientFactory(fake_reactor, dummy_transport, pki)
    client = client_factory.build(EchoClientProtocol())

    # test client send
    dest = pki.get_consensus().keys()[0]
    route = generate_route(params, pki, dest)
    client.messageSend(route, {'text' : b'ping'})

    assert len(dummy_transport.sent) == 1
    assert len(dummy_transport.sent[0]) > 1271
