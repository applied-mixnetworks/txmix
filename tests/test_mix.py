# -*- coding: utf-8 -*-

from zope.interface import implementer

from sphinxmixcrypto import generate_node_keypair, generate_node_id_name
from sphinxmixcrypto import rand_subset, SphinxNodeState

from txmix import IPKIClient, NodeDescriptor, IMixTransport, ClientFactory
from txmix import NodeFactory

import binascii


class NodeTransportMismatchError(Exception):
    """
    """


class NymserverTransportMismatchError(Exception):
    """
    """


@implementer(IMixTransport)
class DummyTransport(object):

    name = "dummy"

    def __init__(self):
        self.received_callback = None
        self.receive = []
        self.sent = []

    def start(self, addr, protocol):
        self.received_callback = protocol.message_received

    def received(self, message):
        print("dummy transport received message len %s" % len(message))
        self.receive.append(message)
        self.received_callback(message)

    def send(self, addr, message):
        print("dummy transport send message len %s to addr %s" % (len(message), addr))
        self.sent.append((addr, message))


@implementer(IPKIClient)
class FakePKI():
    consensus = None

    def __init__(self, nymserver_addr, nymserver_transport):
        self.nymserver_addr = nymserver_addr
        self.nymserver_transport = nymserver_transport

    def set_consensus(self, consensus):
        self.consensus = consensus

    def get_consensus(self):
        return self.consensus

    def register(self, mix_descriptor):
        pass

    def get_mix_addr(self, transport_name, node_id):
        node_descriptor = self.consensus[node_id]
        if node_descriptor.transport_name != transport_name:
            raise NodeTransportMismatchError
        return node_descriptor.addr

    def get_nymserver_addr(self, transport_name):
        if self.nymserver_transport != transport_name:
            raise NymserverTransportMismatchError("failed to get nymserver address")
        return self.nymserver


def build_mixnet_nodes(params, node_factory):
    """
    i am a helper function used to build a testing mix network.
    given the sphinx params and a node_factory i will return
    a dictionary of NodeDescriptors, a dictionary of node protocols
    and a dictionary of addr -> node protocol
    """
    mix_size = 40
    consensus = {}
    nodes = {}
    addr_to_nodes = {}
    for i in range(mix_size):
        node_state = SphinxNodeState()
        public_key, private_key = generate_node_keypair(params.group)
        node_id, node_name = generate_node_id_name(params.k)
        node_state.private_key = private_key
        node_state.public_key = public_key
        node_state.id = node_id
        node_state.name = node_name
        addr = i
        dummy_node_transport = DummyTransport()
        node_protocol = node_factory.buildProtocol(FakeMixProtocol(), node_state, dummy_node_transport, addr)
        nodes[node_id] = node_protocol
        node_descriptor = NodeDescriptor(node_id, public_key, "dummy", addr)
        consensus[node_descriptor.id] = node_descriptor
        addr_to_nodes[addr] = node_protocol
    return nodes, consensus, addr_to_nodes

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
        if message == b"ping":
            print("ping received")
            return
        print("non-ping received")
        # XXX send a reply ping
        #outgoing_message = {'message':'ping'}
        #self.transport.send(message['surb'], outgoing_message)

class FakeMixProtocol(object):
    sent_mix = []
    sent_exit_mix = []
    sent_nymserver = []

    def setTransport(self, transport):
        self.transport = transport

    def send_to_exit_mix(self, destination, sphinx_message):
        self.sent_exit_mix.append((destination, sphinx_message))

    def send_to_mix(self, destination, sphinx_message):
        self.sent_mix.append((destination, sphinx_message))

    def send_to_nymserver(self, nym_id, message):
        self.sent_nymserver.append((nym_id, message))

    def messageResultReceived(self, messageResult):
        if messageResult.tuple_next_hop:
            nextHop, header, delta = messageResult.tuple_next_hop
            alpha, beta, gamma = header
            sphinx_message = {
                "alpha": alpha,
                "beta": beta,
                "gamma": gamma,
                "delta": delta,
            }
            self.send_to_mix(nextHop, sphinx_message)
        elif messageResult.tuple_exit_hop:
            destination, message = messageResult.tuple_exit_hop
            sphinx_message = {
                "alpha": None,
                "beta": None,
                "gamma": None,
                "delta": message,
            }
            self.send_to_exit_mix(destination, sphinx_message)
        else:
            assert messageResult.tuple_client_hop
            nym_id, message = messageResult.tuple_client_hop
            self.send_to_nymserver(nym_id, message)
    def messageSend(self, destination, message):
        pass

def test_NodeProtocol():
    pki = FakePKI(None, None)
    node_factory = NodeFactory(pki)
    params = node_factory.params
    nodes, consensus, addr_to_nodes = build_mixnet_nodes(params, node_factory)
    pki.set_consensus(consensus)

    dummy_client_transport = DummyTransport()
    client_factory = ClientFactory(dummy_client_transport, pki)
    client = client_factory.buildProtocol(EchoClientProtocol(), "fake_client_addr")

    dest = pki.get_consensus().keys()[0]
    route = generate_route(params, pki, dest)
    message = b"ping"
    client.send(route, message)

    dest_addr, message = dummy_client_transport.sent.pop()
    print("dummy client transport sending message to %s" % dest_addr)
    node_protocol = addr_to_nodes[dest_addr]
    node_protocol.transport.received(message)

    while True:
        try:
            destination, message = node_protocol.protocol.sent_mix.pop()
        except IndexError:
            break
        node_protocol.send_to_mix(destination, message)
        destination, message = node_protocol.transport.sent.pop()

        node_protocol = addr_to_nodes[destination]
        node_protocol.transport.received(message)

    destination, message = node_protocol.protocol.sent_exit_mix.pop()
    deserialized_message = message['delta']
    print("exit node delivers %s to %s" % (deserialized_message, binascii.hexlify(destination)))
