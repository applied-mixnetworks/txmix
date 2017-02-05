# -*- coding: utf-8 -*-

import os
import zope.interface
from zope.interface import implementer
import binascii

from sphinxmixcrypto.common import RandReader
from sphinxmixcrypto import PacketReplayCacheDict, IKeyState, IMixPKI, GroupCurve25519, SphinxParams, SECURITY_PARAMETER, sphinx_packet_unwrap
from sphinxmixcrypto import create_forward_message

from txmix import IMixTransport, ClientFactory
from txmix.node import NodeFactory, ThreshMixNode
from txmix.common import sphinx_packet_decode, sphinx_packet_encode



def generate_node_id(rand_reader):
    idnum = rand_reader.read(4)
    node_id = b"\xff" + idnum + (b"\x00" * (SECURITY_PARAMETER - len(idnum) - 1))
    return node_id

def generate_node_keypair(rand_reader):
    group = GroupCurve25519()
    private_key = group.gensecret(rand_reader)
    public_key = group.expon(group.generator, private_key)
    return public_key, private_key


@implementer(IKeyState)
class SphinxNodeKeyState:

    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key

    def get_private_key(self):
        return self.private_key

    def get_public_key(self):
        return self.public_key


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


@implementer(IMixTransport)
class DummyTransport(object):

    name = "dummy"

    def __init__(self, addr):
        self.received_callback = None
        self.receive = []
        self.sent = []
        self.addr = addr

    def register_protocol(self, protocol):
        self.protocol = protocol

    def start(self):
        pass

    def received(self, message):
        self.receive.append(message)
        self.protocol.sphinx_packet_received(message)

    def send(self, addr, message):
        self.sent.append((addr, message))


@implementer(IMixPKI)
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
    mix_size = 5
    nodes = {}
    addr_to_nodes = {}
    for i in range(mix_size):
        addr = i
        public_key, private_key = generate_node_keypair(rand_reader)
        replay_cache = PacketReplayCacheDict()
        key_state = SphinxNodeKeyState(public_key, private_key)
        params = SphinxParams(5, 1024) # 5 hops max and payload 1024 bytes
        transport = DummyTransport(i)
        node_id = generate_node_id(rand_reader)
        mix = ThreshMixNode(node_id, replay_cache, key_state, params, pki, transport)
        mix.start()
        nodes[node_id] = mix
        addr_to_nodes[addr] = mix
    route = nodes.keys()[:5]
    return nodes, addr_to_nodes, route

def rand_subset(lst, nu):
    """
    Return a list of nu random elements of the given list (without
    replacement).
    """
    # Randomize the order of the list by sorting on a random key
    nodeids = [(os.urandom(8), x) for x in lst]
    nodeids.sort(key=lambda x: x[0])
    # Return the first nu elements of the randomized list
    return [x[1] for x in nodeids[:nu]]

def generate_route(params, pki, destination):
    """
    given a destination node ID a randomly chosen
    route is returned: a list of mix node IDs
    where the last element is the destination
    """
    mixes = pki.identities()
    mixes.remove(destination)
    return rand_subset(mixes, params.max_hops - 1) + [destination]


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
    rand_reader = FixedNoiseReader("b5451d2eb2faf3f84bc4778ace6516e73e9da6c597e6f96f7e63c7ca6c9456018be9fd84883e4469a736c66fcaeceacf080fb06bc45859796707548c356c462594d1418b5349daf8fffe21a67affec10c0a2e3639c5bd9e8a9ddde5caf2e1db802995f54beae23305f2241c6517d301808c0946d5895bfd0d4b53d8ab2760e4ec8d4b2309eec239eedbab2c6ae532da37f3b633e256c6b551ed76321cc1f301d74a0a8a0673ea7e489e984543ca05fe0ff373a6f3ed4eeeaafd18292e3b182c25216aeb80a9411a57044d20b6c4004c730a78d79550dc2f22ba1c9c05e1d15e0fcadb6b1b353f028109fd193cb7c14af3251e6940572c7cd4243977896504ce0b59b17e8da04de5eb046a92f1877b55d43def3cc11a69a11050a8abdceb45bc1f09a22960fdffce720e5ed5767fbb62be1fd369dcdea861fd8582d01666a08bf3c8fb691ac5d2afca82f4759029f8425374ae4a4c91d44d05cb1a64193319d9413de7d2cfdffe253888535a8493ab8a0949a870ae512d2137630e2e4b2d772f6ee9d3b9d8cadd2f6dc34922701b21fa69f1be6d0367a26ca")

    nodes, addr_to_nodes, route = build_mixnet_nodes(pki, params, node_factory, rand_reader)

    dummy_client_transport = DummyTransport(99)
    client_factory = ClientFactory(dummy_client_transport, pki, rand_reader)
    client_id = binascii.unhexlify("436c69656e74206564343564326264")
    client = client_factory.buildProtocol(EchoClientProtocol(), client_id)

    message = b"ping"
    first_hop_addr = pki.get_mix_addr("dummy", route[0])
    client.send(route, message)
    destination, raw_sphinx_packet = dummy_client_transport.sent.pop()

    sphinx_packet = sphinx_packet_decode(params, raw_sphinx_packet)
    nodes[route[0]].protocol.sphinx_packet_received(raw_sphinx_packet)
