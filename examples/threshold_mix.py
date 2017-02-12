
from twisted.internet import reactor

from sphinxmixcrypto import PacketReplayCacheDict, SphinxParams

from txmix import UDPTransport
from txmix import ThresholdMixNode
from txmix import RandReader, generate_node_keypair, generate_node_id, DummyPKI, SphinxNodeKeyState


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
