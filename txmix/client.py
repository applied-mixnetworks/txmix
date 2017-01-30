
from __future__ import print_function

import os

from sphinxmixcrypto import SphinxClient, create_forward_message
from txmix.common import DEFAULT_CRYPTO_PARAMETERS, sphinx_packet_encode


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


class ClientFactory(object):
    """
    Factory class for creating mix clients
    with parameterized transports, pki and sphinx crypto primitives
    """
    def __init__(self, transport, pki, rand_reader, params=None):
        self.transport = transport
        self.rand_reader = rand_reader
        self.pki = pki

        if params is None:
            self.params = DEFAULT_CRYPTO_PARAMETERS
        else:
            self.params = params

    def buildProtocol(self, protocol, addr, client_id):
        client_protocol = ClientProtocol(self.params, self.pki, client_id, self.rand_reader, self.transport)
        protocol.setTransport(self.transport)
        self.transport.start(addr, client_protocol)
        return client_protocol


class ClientProtocol(object):
    """
    I am a sphinx mix network client protocol which
    means I have a producer/consumer relationship with
    a sphinx mix network client transport.
    """
    def __init__(self, params, pki, client_id, rand_reader, transport):
        self.params = params
        self.sphinx_client = SphinxClient(params, client_id, rand_reader=rand_reader)
        self.rand_reader = rand_reader
        self.pki = pki
        self.transport = transport

    def message_received(self, nym_id, delta):
        unwrapped_message = self.sphinx_client.decrypt(nym_id, delta)
        self.protocol.messageReceived(unwrapped_message)

    def send(self, route, message):
        first_hop_addr = self.pki.get_mix_addr(self.transport.name, route[0])
        alpha, beta, gamma, delta = create_forward_message(self.params, route, self.pki, route[-1], message, self.rand_reader)
        serialized_sphinx_packet = encode_sphinx_packet(alpha, beta, gamma, delta)
        self.transport.send(first_hop_addr, serialized_sphinx_packet)
