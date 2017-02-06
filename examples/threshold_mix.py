
from twisted.internet import reactor
from zope.interface.declarations import implementer

from sphinxmixcrypto import IMixPKI, GroupCurve25519, IKeyState, SECURITY_PARAMETER
from sphinxmixcrypto import PacketReplayCacheDict, SphinxParams, RandReader

from txmix.transports import UDPTransport
from txmix.node import ThresholdMixNode


@implementer(IKeyState)
class SphinxNodeKeyState:

    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key

    def get_private_key(self):
        return self.private_key

    def get_public_key(self):
        return self.public_key


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


def generate_node_keypair(rand_reader):
    group = GroupCurve25519()
    private_key = group.gensecret(rand_reader)
    public_key = group.expon(group.generator, private_key)
    return public_key, private_key


def generate_node_id(rand_reader):
    idnum = rand_reader.read(4)
    node_id = b"\xff" + idnum + (b"\x00" * (SECURITY_PARAMETER - len(idnum) - 1))
    return node_id


def main():
    rand_reader = RandReader()
    public_key, private_key = generate_node_keypair(rand_reader)
    node_id = generate_node_id(rand_reader)

    replay_cache = PacketReplayCacheDict()
    key_state = SphinxNodeKeyState(public_key, private_key)
    params = SphinxParams(5, 1024)  # 5 hops max and payload 1024 bytes
    pki = DummyPKI()

    # interface and port to listen on for UDP packets
    transport = UDPTransport(reactor, ("127.0.0.1", 6789))
    threshold_count = 100

    mix = ThresholdMixNode(threshold_count, node_id, replay_cache, key_state, params, pki, transport)
    mix.start()
    reactor.run()


if __name__ == '__main__':
    main()
