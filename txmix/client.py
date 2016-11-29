
from __future__ import print_function

from sphinxmixcrypto import SphinxParams, GroupECC, Chacha_Lioness, Chacha20_stream_cipher, Blake2_hash
from sphinxmixcrypto import rand_subset, SphinxClient, create_forward_message

from txmix import CBOREncodingHandler


class MixClientFactory(object):
    """
    Factory class for creating mix clients
    with parameterized transports and pki.

    Uses the sphinx mix packet format with:
    CBOR serialization format,
    curve25519 public keys, blake2b hash,
    chacha20 stream cipher, lioness wide block
    cipher composed using blake2b and chacha20
    """
    def __init__(self, reactor, transport, pki):
        self.reactor = reactor
        self.transport = transport
        self.pki = pki

    @classmethod
    def from_transport(cls, transport):
        return cls(transport=transport)

    def build(self, protocol):
        hops = 5 # XXX
        params = SphinxParams(
            hops, group_class = GroupECC,
            hash_func = Blake2_hash,
            lioness_class = Chacha_Lioness,
            stream_cipher = Chacha20_stream_cipher,
        )
        client = SphinxClientProtocol(params, self.pki, self.transport, CBOREncodingHandler())
        protocol.setTransport(self.transport)
        self.transport.setClient(client)
        self.transport.start()
        return client


class SphinxClientProtocol(object):
    """
    I am a sphinx mix network client protocol which
    means I have a producer/consumer relationship with
    a sphinx mix network client transport. My only responsibility
    to take care of encryption and serialization of messages.
    """
    def __init__(self, params, pki, transport, encoding):
        self.params = params
        self.sphinx_client = SphinxClient(params)
        self.pki = pki
        self.transport = transport
        self.encoding = encoding

    def messageReceived(self, message):
        nym_id, delta = self.encoding.deserialize(message)
        unwrapped_message = self.sphinx_client.decrypt(nym_id, delta)
        self.protocol.messageReceived(unwrapped_message)

    def messageSend(self, route, message):
        serialized_message = self.encoding.serialize(message)
        first_hop_addr = self.pki.getAddr(self.transport.name, route[0])
        consensus = self.pki.get_consensus()
        node_map = {}
        for node_id, node_desc in consensus.items():
            node_map[node_id] = node_desc.public_key
        alpha, beta, gamma, delta = create_forward_message(self.params, route, node_map, route[-1], serialized_message)
        sphinx_packet = {
            "alpha": alpha,
            "beta" : beta,
            "gamma": gamma,
            "delta": delta,
        }
        serialized_sphinx_packet = self.encoding.serialize(sphinx_packet)
        self.transport.send(first_hop_addr, serialized_sphinx_packet)
