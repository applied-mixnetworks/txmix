
from __future__ import print_function

from sphinxmixcrypto import rand_subset, SphinxClient, create_forward_message
from txmix.common import DEFAULT_CRYPTO_PARAMETERS, SphinxPacketEncoding


class ClientFactory(object):
    """
    Factory class for creating mix clients
    with parameterized transports, pki and sphinx crypto primitives
    """
    def __init__(self, reactor, transport, pki, params=None):
        self.reactor = reactor
        self.transport = transport
        self.pki = pki

        if params is None:
            self.params = DEFAULT_CRYPTO_PARAMETERS
        else:
            self.params = params

    def buildProtocol(self, protocol, addr):
        client_protocol = ClientProtocol(self.params, self.pki, self.transport)
        protocol.setTransport(self.transport)
        self.transport.setProtocol(client_protocol)
        self.transport.listen(self.reactor, addr)
        return client_protocol


class ClientProtocol(object):
    """
    I am a sphinx mix network client protocol which
    means I have a producer/consumer relationship with
    a sphinx mix network client transport. My only responsibility
    is to take care of encryption and serialization of messages.
    """
    def __init__(self, params, pki, transport):
        self.params = params
        self.sphinx_client = SphinxClient(params)
        self.pki = pki
        self.transport = transport
        self.encoding = SphinxPacketEncoding(params)

        consensus = self.pki.get_consensus()
        self.node_key_map = {}
        for node_id, node_desc in consensus.items():
            self.node_key_map[node_id] = node_desc.public_key

    def messageReceived(self, message):
        # XXX fix me
        #nym_id, delta = self.encoding.deserialize(message)
        unwrapped_message = self.sphinx_client.decrypt(nym_id, delta)
        self.protocol.messageReceived(unwrapped_message)

    def messageSend(self, route, message):
        print("messageSend")
        first_hop_addr = self.pki.getAddr(self.transport.name, route[0])
        alpha, beta, gamma, delta = create_forward_message(self.params, route, self.node_key_map, route[-1], message)
        serialized_sphinx_packet = self.encoding.packetEncode(alpha, beta, gamma, delta)
        self.transport.send(first_hop_addr, serialized_sphinx_packet)
