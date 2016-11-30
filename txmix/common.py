
from __future__ import print_function

from sphinxmixcrypto import SphinxParams, GroupECC, Chacha_Lioness, Chacha20_stream_cipher, Blake2_hash


DEFAULT_CRYPTO_PARAMETERS = SphinxParams(
    5, group_class = GroupECC, # 5 hops
    hash_func = Blake2_hash,
    lioness_class = Chacha_Lioness,
    stream_cipher = Chacha20_stream_cipher,
)


class NodeDescriptor(object):

    def __init__(self, id, pub_key, transport_name, addr):
        self.id = id
        self.public_key = pub_key
        self.transport_name = transport_name
        self.addr = addr


class SphinxPacketEncoding(object):

    def __init__(self, params):
        self.params = params

    def packetDecode(self, packet):
        alpha, beta, gamma, delta = self.params.get_dimensions()
        sphinx_packet = {}
        sphinx_packet['alpha'] = packet[:alpha]
        sphinx_packet['beta']  = packet[alpha:alpha+beta]
        sphinx_packet['gamma'] = packet[alpha+beta:alpha+beta+gamma]
        sphinx_packet['delta'] = packet[alpha+beta+gamma:]
        return sphinx_packet

    def packetEncode(self, alpha, beta, gamma, delta):
        return alpha + beta + gamma + delta
