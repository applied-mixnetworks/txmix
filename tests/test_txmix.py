# -*- coding: utf-8 -*-

import os
import zope.interface
from zope.interface import implementer
import binascii

from sphinxmixcrypto.common import RandReader
from sphinxmixcrypto import PacketReplayCacheDict, IMixPrivateKey, IMixPKI, GroupCurve25519, SphinxParams, SECURITY_PARAMETER

from txmix import IMixTransport, ClientFactory
from txmix.node import NodeFactory, ThreshMixNode


def generate_node_id(rand_reader):
    idnum = rand_reader.read(4)
    node_id = b"\xff" + idnum + (b"\x00" * (SECURITY_PARAMETER - len(idnum) - 1))
    return node_id

def generate_node_keypair(rand_reader):
    group = GroupCurve25519()
    private_key = group.gensecret(rand_reader)
    public_key = group.expon(group.generator, private_key)
    return public_key, private_key


@implementer(IMixPrivateKey)
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
    mix_size = 40
    nodes = {}
    addr_to_nodes = {}
    for i in range(mix_size):
        addr = i
        public_key, private_key = generate_node_keypair(rand_reader)
        replay_cache = PacketReplayCacheDict()
        key_state = SphinxNodeKeyState(private_key)
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
    rand_reader = FixedNoiseReader("b5451d2eb2faf3f84bc4778ace6516e73e9da6c597e6f96f7e63c7ca6c9456018be9fd84883e4469a736c66fcaeceacf080fb06bc45859796707548c356c462594d1418b5349daf8fffe21a67affec10c0a2e3639c5bd9e8a9ddde5caf2e1db802995f54beae23305f2241c6517d301808c0946d5895bfd0d4b53d8ab2760e4ec8d4b2309eec239eedbab2c6ae532da37f3b633e256c6b551ed76321cc1f301d74a0a8a0673ea7e489e984543ca05fe0ff373a6f3ed4eeeaafd18292e3b182c25216aeb80a9411a57044d20b6c4004c730a78d79550dc2f22ba1c9c05e1d15e0fcadb6b1b353f028109fd193cb7c14af3251e6940572c7cd4243977896504ce0b59b17e8da04de5eb046a92f1877b55d43def3cc11a69a11050a8abdceb45bc1f09a22960fdffce720e5ed5767fbb62be1fd369dcdea861fd8582d01666a08bf3c8fb691ac5d2afca82f4759029f8425374ae4a4c91d44d05cb1a64193319d9413de7d2cfdffe253888535a8493ab8a0949a870ae512d2137630e2e4b2d772f6ee9d3b9d8cadd2f6dc34922701b21fa69f1be6d0367a26c2875cb7afffe60d59597cc084854beebd80d559cf14fcb6642c4ab9102b2da409685f5ca9a23b6c718362ccd6405d993dbd9471b4e7564631ce714d9c022852113268481930658e5cee6d2538feb9521164b2b1d4d68c76967e2a8e362ef8f497d521ee0d57bcd7c8fcc4c673f8f8d700c9c71f70c73194f2eddf03f954066372918693f8e12fc980e1b8ad765c8806c0ba144b86277170b12df16b47de5a2596b2149c4408afbe8f790d3cebf1715d1c4a9ed5157b130a66a73001f6f344c74438965e85d3cac84932082e6b17140f6eb901e3de7b3a16a76bdde2972c557d573830e8a455973de43201b562f63f5b3dca8555b5215fa138e81da900358ddb4d123b57b4a4cac0bfebc6ae3c7d54820ca1f3ee9908f7cb81200afeb1fdafdfbbc08b15d8271fd18cfd7344b36bdd16cca082235c3790888dae22e547bf436982c1a1935e2627f1bb16a3b4942f474d2ec1ff15eb6c3c4e320892ca1615ecd462007e51fbc69817719e6d641c101aa153bff207974bbb4f9553a8d6fb0cfa2cb1a497f9eee32f7c084e97256c72f06f020f33a0c079f3f69c2ce0e2826cc396587d80c9485e26f70633b70ad2e2d531a44407d101628c0bdae0cd47d6032e97b73e1231c3db06a2ead13eb20878fc198a345dd9dafc54b0cc56bcf9aa64e85002ff91a3f01dc97de5e85d68707a4909385cefbd6263cf9624a64d9052291da48d33ac401854cce4d6a7d21be4b5f1f4616e1784226603fdadd45d802ab226c81ec1fc1827310c2c99ce1c7ee28f38fbc7cf637132a1a2b1e5835762b41f0c7180a7738bac5cedebc11cdbf229e2155a085349b93cb94ce4285ea739673cc719e46cacb56663564057df1a0a2f688ed216336ff695337d6922f0185c23c3c04294388da192d9ae2b51ff18a8cc4d3212e1b2b19fed7b8f3662c2f9bd463f75e1e7c738db6b204f8f5aa8176e238d41c8d828b124e78c294be2d5b2bf0724958b787b0bea98d9a1534fc9975d66ee119b47b2e3017c9bba9431118c3611840b0ddcb00450024d484080d29c3896d92913eaca52d67f313a482fcc6ab616673926bdbdb1a2e62bcb055755ae5b3a975996e40736fde300717431c7d7b182369f90a092aef94e58e0ea5a4b15e76d9f486475acc1bd3bc551700f58108ea4029a250b5e893eaaf8aeb0811d84094816b3904f69d45921448454de0eb18bfda49832492a127a5682231d3848a3cb06ca17c3427063f80d662997b30bc9307a676cd6972716d1d6ee59b657f368b0fdb0245872e5157dd3de788341518c328395b415b516bd47efb86302edf840eebd9de432e08d6b9fddd4d55f75112332e403d78e536193aa172c0dbffbc9631d8c877214abef61d54bd0a35114e5f0eace320e9422cb6ecdc8de8cebacf32dd676d9e8142070856275ff39efaa0de2eb3b5bb4fa65df8d775d606705ccf0ce8f66a444f04dfaee50c0d23c4ae1b217bf28e49db77df4b91aba049514ed1c8f55648f176b4a9d3045433d838063a830523e6e5bdc53e0278734436df2a3936df05b2ae68fadf26e7913216606ec1dbc")

    nodes, addr_to_nodes, route = build_mixnet_nodes(pki, params, node_factory, rand_reader)

    dummy_client_transport = DummyTransport(99)
    client_factory = ClientFactory(dummy_client_transport, pki, rand_reader)
    client_id = binascii.unhexlify("436c69656e74206564343564326264")
    client = client_factory.buildProtocol(EchoClientProtocol(), client_id)

    message = b"ping"
    first_hop_addr = pki.get_mix_addr("dummy", route[0])
    client.send(route, message)
    destination, message = dummy_client_transport.sent.pop()
    print "YOYO first hope addr %s" % destination
    mix = addr_to_nodes[destination]
    print "mix node id %s" % binascii.hexlify(mix.node_id)
    mix.protocol.sphinx_packet_received(message)
