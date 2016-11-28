
from __future__ import print_function

from txmix import UDPClientTransport, Client


class UDPClient(object):
    """
    UDP mix client
    """

    def __init__(self, reactor, interface, port, received_callback, params, pki, encoding_handler):
        self.reactor = reactor
        self.interface = interface
        self.port = port
        self.received_callback = received_callback
        self.params = params
        self.pki = pki
        self.encoding_handler = encoding_handler
        self.transport = UDPClientTransport(self.received)
        
    def start(self):
        self.client = Client(self.params, self.pki, self.transport, self.encoding_handler)
        self.reactor.listenUDP(self.port, self.transport, interface=self.interface)

    def received(self, message):
        self.received_callback(self.client.received(message))

    def send(self, node_id, message):
        self.client.send(node_id, message)
