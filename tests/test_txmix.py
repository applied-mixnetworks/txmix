# -*- coding: utf-8 -*-

import zope.interface
from zope.interface import implementer
import binascii

from sphinxmixcrypto.common import RandReader
from sphinxmixcrypto import PacketReplayCacheDict, IMixPrivateKey, IMixPKI, GroupCurve25519

from txmix import IMixTransport, ClientFactory
from txmix import NodeFactory


def generate_node_id(id_length, idnum):
    """
    generate a new node id
    """
    node_id = b"\xff" + idnum + (b"\x00" * (id_length - len(idnum) - 1))
    return node_id

def generate_node_id_name(id_len, rand_reader):
    idnum = rand_reader.read(4)
    id = generate_node_id(id_len, idnum)
    name = "Node " + str(binascii.b2a_hex(idnum))
    return id, name


def generate_node_keypair(rand_reader):
    group = GroupCurve25519()
    private_key = group.gensecret(rand_reader)
    public_key = group.expon(group.generator, private_key)
    return public_key, private_key


@zope.interface.implementer(IMixPrivateKey)
class SphinxNodeKeyState:

    def __init__(self, private_key):
        self.private_key = private_key

    def get_private_key(self):
        return self.private_key


class FixedNoiseReader():

    def __init__(self, hexed_noise):
        self.noise = binascii.unhexlify(hexed_noise)
        self.count = 0
        self.fallback = RandReader()

    def read(self, n):
        if n > len(self.noise):
            print("%s > %s" % (n, len(self.noise)))
            return self.fallback.read(n)
        ret = self.noise[:n]
        self.noise = self.noise[n:]
        self.count += n
        return ret


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


@zope.interface.implementer(IMixPKI)
class DummyPKI(object):

    def __init__(self):
        self.node_map = {}
        self.addr_map = {}

    def set(self, key_id, pub_key, addr):
        assert key_id not in self.node_map.keys()
        self.node_map[key_id] = pub_key
        self.addr_map[key_id] = addr

    def get(self, key_id):
        return self.node_map[key_id]

    def identities(self):
        return self.node_map.keys()

    def get_mix_addr(self, transport_name, key_id):
        return self.addr_map[key_id]

    def rotate(self, key_id, new_key_id, new_pub_key, signature):
        pass


def build_mixnet_nodes(pki, params, node_factory, rand_reader):
    """
    i am a helper function used to build a testing mix network.
    given the sphinx params and a node_factory i will return
    a dictionary of NodeDescriptors, a dictionary of node protocols
    and a dictionary of addr -> node protocol
    """
    mix_size = 40
    nodes = {}
    addr_to_nodes = {}
    for i in range(mix_size):
        addr = i
        public_key, private_key = generate_node_keypair(rand_reader)
        node_id, name = generate_node_id_name(16, rand_reader)
        replay_cache = PacketReplayCacheDict()
        dummy_node_transport = DummyTransport()
        replay_cache = PacketReplayCacheDict()
        key_state = SphinxNodeKeyState(private_key)
        node_protocol = node_factory.buildProtocol(FakeMixProtocol(), replay_cache, key_state, dummy_node_transport, addr)
        nodes[node_id] = node_protocol
        pki.set(node_id, public_key, addr)
        addr_to_nodes[addr] = node_protocol
    return nodes, addr_to_nodes


def generate_route(params, pki, destination):
    """
    given a destination node ID a randomly chosen
    route is returned: a list of mix node IDs
    where the last element is the destination
    """
    return rand_subset(pki.identities(), params.max_hops - 1) + [destination]


class EchoClientProtocol(object):
    def setTransport(self, transport):
        self.transport = transport

    def messageReceived(self, message):
        if message == b"ping":
            print("ping received")
            return
        print("non-ping received")
        #  XXX send a reply ping
        #  outgoing_message = {'message':'ping'}
        #  self.transport.send(message['surb'], outgoing_message)


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
    pki = DummyPKI()
    node_factory = NodeFactory(pki)
    params = node_factory.params
    rand_reader = RandReader()
    nodes, addr_to_nodes = build_mixnet_nodes(pki, params, node_factory, rand_reader)
    dummy_client_transport = DummyTransport()
    client_factory = ClientFactory(dummy_client_transport, pki, rand_reader)
    client_id = binascii.unhexlify("436c69656e74206564343564326264")
    client = client_factory.buildProtocol(EchoClientProtocol(), "fake_client_addr", client_id)

    dest = pki.identities()[0]
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
