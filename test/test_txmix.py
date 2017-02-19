# -*- coding: utf-8 -*-

import binascii
import json
import sys
import pytest

from eliot import add_destination
from Cryptodome.Cipher import ChaCha20
from twisted.internet import defer
from zope.interface import implementer

from sphinxmixcrypto import PacketReplayCacheDict, GroupCurve25519, SphinxParams, SECURITY_PARAMETER
from sphinxmixcrypto import IReader, IKeyState

from txmix.interfaces import IMixTransport
from txmix.mix import ThresholdMixNode
from txmix.client import MixClient, RandomRouteFactory
from txmix.utils import DummyPKI


# tell eliot to log a line of json for each message to stdout
def stdout(message):
    sys.stdout.write(json.dumps(message) + "\n")


add_destination(stdout)


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
class ChachaNoiseReader():
    """
    hello, i am an entropy "iterator". sphinx uses a source of entropy
    for generation of key material. i'm deterministic so use me to
    write deterministic tests.
    """
    def __init__(self, seed_string):
        assert isinstance(seed_string, str) and len(seed_string) == 64
        self.cipher = ChaCha20.new(key=binascii.unhexlify(seed_string), nonce=b"\x00" * 8)

    def read(self, n):
        return self.cipher.encrypt(b"\x00" * n)


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
        return defer.succeed(None)

    def received(self, message):
        self.receive.append(message)
        self.protocol.received(message)

    def send(self, addr, message):
        self.sent.append((addr, message))
        return defer.succeed(None)


@defer.inlineCallbacks
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
        yield mix.start()
        nodes[node_id] = mix
        addr_to_nodes[addr] = mix
    defer.returnValue((nodes, addr_to_nodes))


@pytest.inlineCallbacks
def test_node_protocol():
    pki = DummyPKI()
    params = SphinxParams(5, 1024)
    rand_reader = ChachaNoiseReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")

    nodes, addr_to_nodes = yield build_mixnet_nodes(pki, params, rand_reader)
    dummy_client_transport = DummyTransport(99)
    client_id = "Client 555"
    # XXX todo: make deterministic route
    # route_factory = FakeRouteFactory()
    route_factory = RandomRouteFactory(params, pki, rand_reader)

    def received(packet):
        print "received packet of len %s" % len(packet)

    client = MixClient(params, pki, client_id, rand_reader, dummy_client_transport, lambda x: received(x), route_factory)
    yield client.start()
    message = b"ping"
    destination = pki.identities()[0]
    yield client.send(destination, message)
    address, raw_sphinx_packet = dummy_client_transport.sent.pop()
    addr_to_nodes[address].protocol.received(raw_sphinx_packet)
