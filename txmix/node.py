
from __future__ import print_function

from sphinxmixcrypto import sphinx_packet_unwrap
from txmix.common import DEFAULT_CRYPTO_PARAMETERS, encode_sphinx_packet, decode_sphinx_packet


class NodeFactory(object):
    """
    Factory class for creating mixes.
    """
    def __init__(self, pki, params=None):
        self.pki = pki
        if params is None:
            self.params = DEFAULT_CRYPTO_PARAMETERS
        else:
            self.params = params

    def buildProtocol(self, protocol, replay_cache, key_state, transport, addr):
        node_protocol = NodeProtocol(replay_cache, key_state, self.params, self.pki, transport)
        node_protocol.set_protocol(protocol)
        protocol.setTransport(node_protocol)
        transport.start(addr, node_protocol)
        return node_protocol


class NodeProtocol(object):
    """
    i am a mix net node protocol responsible for encryption
    and serialization of mix messages.
    """

    def __init__(self, replay_cache, key_state, params, pki, transport):
        self.replay_cache = replay_cache
        self.key_state = key_state
        self.params = params
        self.pki = pki
        self.transport = transport
        self.protocol = None

    def set_protocol(self, application_protocol):
        self.protocol = application_protocol

    def message_received(self, message):
        """
        i receive messages and proxy them
        to my attached protocol after deserializing and unwrapping
        """
        sphinx_packet = decode_sphinx_packet(self.params, message)
        message_result = sphinx_packet_unwrap(self.params, self.replay_cache, self.key_state, sphinx_packet)
        self.protocol.messageResultReceived(message_result)

    def send_to_mix(self, destination, message):
        serialized_message = encode_sphinx_packet(message['alpha'], message['beta'], message['gamma'], message['delta'])
        addr = self.pki.get_mix_addr(self.transport.name, destination)
        self.transport.send(addr, serialized_message)

    def send_to_nymserver(self, nym_id, message):
        pass

    def send_to_client(self, client_id, message_id, message):
        pass
