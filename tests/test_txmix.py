# -*- coding: utf-8 -*-

import os
import binascii
from zope.interface import implementer

from sphinxmixcrypto import PacketReplayCacheDict, GroupCurve25519, SphinxParams, SECURITY_PARAMETER
from sphinxmixcrypto import IReader, IKeyState, IMixPKI

from txmix import IMixTransport
from txmix import ThresholdMixNode, ClientProtocol, MixClient


@implementer(IReader)
class RandReader:
    def __init__(self):
        pass

    def read(self, n):
        return os.urandom(n)


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


@implementer(IReader)
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
        self.protocol.received(message)

    def send(self, addr, message):
        self.sent.append((addr, message))


@implementer(IMixPKI)
class DummyPKI(object):

    def __init__(self):
        self.node_map = {}
        self.addr_map = {}

    def set(self, node_id, pub_key, addr):
        assert node_id not in self.node_map.keys()
        self.node_map[node_id] = pub_key
        self.addr_map[node_id] = addr

    def get(self, node_id):
        return self.node_map[node_id]

    def identities(self):
        return self.node_map.keys()

    def get_mix_addr(self, transport_name, node_id):
        return self.addr_map[node_id]

    def rotate(self, node_id, new_pub_key, signature):
        pass


def build_mixnet_nodes(pki, params, rand_reader):
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
        params = SphinxParams(5, 1024)  # 5 hops max and payload 1024 bytes
        transport = DummyTransport(i)
        node_id = generate_node_id(rand_reader)
        threshold_count = 100
        mix = ThresholdMixNode(threshold_count, node_id, replay_cache, key_state, params, pki, transport)
        mix.start()
        nodes[node_id] = mix
        addr_to_nodes[addr] = mix
    return nodes, addr_to_nodes


def test_NodeProtocol():
    pki = DummyPKI()
    params = SphinxParams(5, 1024)
    rand_reader = FixedNoiseReader("b5451d2eb2faf3f84bc4778ace6516e73e9da6c597e6f96f7e63c7ca6c9456018be9fd84883e4469a736c66fcaeceacf080fb06bc45859796707548c356c462594d1418b5349daf8fffe21a67affec10c0a2e3639c5bd9e8a9ddde5caf2e1db802995f54beae23305f2241c6517d301808c0946d5895bfd0d4b53d8ab2760e4ec8d4b2309eec239eedbab2c6ae532da37f3b633e256c6b551ed76321cc1f301d74a0a8a0673ea7e489e984543ca05fe0ff373a6f3ed4eeeaafd18292e3b182c25216aeb80a9411a57044d20b6c4004c730a78d79550dc2f22ba1c9c05e1d15e0fcadb6b1b353f028109fd193cb7c14af3251e6940572c7cd4243977896504ce0b59b17e8da04de5eb046a92f1877b55d43def3cc11a69a11050a8abdceb45bc1f09a22960fdffce720e5ed5767fbb62be1fd369dcdea861fd8582d01666a08bf3c8fb691ac5d2afca82f4759029f8425374ae4a4c91d44d05cb1a64193319d9413de7d2cfdffe253888535a8493ab8a0949a870ae512d2137630e2e4b2d772f6ee9d3b9d8cadd2f6dc34922701b21fa69f1be6d0367a26ca")

    nodes, addr_to_nodes = build_mixnet_nodes(pki, params, rand_reader)
    dummy_client_transport = DummyTransport(99)
    client_id = "Client 555"

    def received(packet):
        print "received packet of len %s" % len(packet)

    client = MixClient(params, pki, client_id, rand_reader, dummy_client_transport, lambda x: received)
    client.start()
    message = b"ping"
    destination = pki.identities()[0]
    client.send(destination, message)
    address, raw_sphinx_packet = dummy_client_transport.sent.pop()
    addr_to_nodes[address].protocol.received(raw_sphinx_packet)
