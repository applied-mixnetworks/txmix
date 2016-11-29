
from __future__ import print_function

from sphinxmixcrypto import rand_subset, SphinxClient, create_forward_message
from txmix.common import DEFAULT_ENCODING_HANDLER, DEFAULT_CRYPTO_PARAMETERS


class ClientFactory(object):
    """
    Factory class for creating mix clients
    with parameterized transports, pki and sphinx crypto primitives
    """
    def __init__(self, reactor, transport, pki, params=None, encoding_handler=None):
        self.reactor = reactor
        self.transport = transport
        self.pki = pki

        if params is None:
            self.params = DEFAULT_CRYPTO_PARAMETERS
        else:
            self.params = params

        if encoding_handler is None:
            self.encoding_handler = DEFAULT_ENCODING_HANDLER
        else:
            self.encoding_handler = encoding_handler

    def build(self, protocol, addr):
        client_protocol = ClientProtocol(self.params, self.pki, self.transport, self.encoding_handler)
        protocol.setTransport(self.transport)
        self.transport.setProtocol(client_protocol)
        self.transport.listen(self.reactor, addr)
        return client_protocol


class ClientProtocol(object):
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
        print("messageSend")
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
