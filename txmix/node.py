
from __future__ import print_function

from sphinxmixcrypto import SphinxNode
from txmix.common import DEFAULT_ENCODING_HANDLER, DEFAULT_CRYPTO_PARAMETERS


class NodeFactory(object):
    def __init__(self, reactor, pki, params=None, encoding_handler=None):
        self.reactor = reactor
        self.pki = pki
        if params is None:
            self.params = DEFAULT_CRYPTO_PARAMETERS
        else:
            self.params = params
        if encoding_handler is None:
            self.encoding_handler = DEFAULT_ENCODING_HANDLER

    def buildProtocol(self, protocol, node_state, transport, addr):
        node_protocol = NodeProtocol(node_state, self.params, self.pki, transport, self.encoding_handler)
        node_protocol.setProtocol(protocol)
        protocol.setTransport(node_protocol)
        transport.setProtocol(node_protocol)
        transport.listen(self.reactor, addr)
        return node_protocol


class NodeProtocol(object):
    """
    i am a mix net node protocol responsible for encryption
    and serialization of mix messages.
    """

    def __init__(self, state, params, pki, transport, encoding):
        self.params = params
        self.sphinx_node = SphinxNode(params, state=state)
        self.pki = pki
        self.transport = transport
        self.encoding = encoding
        self.protocol = None

    def setProtocol(self, application_protocol):
        self.protocol = application_protocol

    def messageReceived(self, message):
        """
        i receive messages and proxy them
        to my attached protocol after deserializing and unwrapping
        """
        sphinx_packet = self.encoding.deserialize_sphinx_packet(message)
        header = sphinx_packet['alpha'], sphinx_packet['beta'], sphinx_packet['gamma']
        message_result = self.sphinx_node.unwrap(header, sphinx_packet['delta'])
        self.protocol.messageResultReceived(message_result)

    def messageSend(self, destination, message):
        print("message send")
        serialized_message = self.encoding.serialize(message)
        addr = self.pki.getAddr(self.transport.name, destination)
        self.transport.send(addr, serialized_message)
