
from __future__ import print_function

from sphinxmixcrypto import SphinxParams, SphinxPacket


DEFAULT_CRYPTO_PARAMETERS = SphinxParams(5, 1024)


class NodeDescriptor(object):

    def __init__(self, id, pub_key, transport_name, addr):
        self.id = id
        self.public_key = pub_key
        self.transport_name = transport_name
        self.addr = addr


def sphinx_packet_decode(params, packet):
    alpha, beta, gamma, delta = params.get_dimensions()
    _alpha = packet[:alpha]
    _beta = packet[alpha:alpha + beta]
    _gamma = packet[alpha + beta:alpha + beta + gamma]
    _delta = packet[alpha + beta + gamma:]
    sphinx_packet = SphinxPacket(_alpha, _beta, _gamma, _delta)
    return sphinx_packet


def sphinx_packet_encode(alpha, beta, gamma, delta):
    return alpha + beta + gamma + delta
