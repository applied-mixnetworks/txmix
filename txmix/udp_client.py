
from __future__ import print_function

from txmix import UDPClientTransport, Client


class UDPClient(object):
    """
    UDP mix client
    """

    def __init__(self, reactor, interface, port, received_callback, pki, encoding):
        self.reactor = reactor
        self.interface = interface
        self.port = port
        self.transport = UDPClientTransport(received_callback)
        self.client = Client(pki, self.transport, encoding)
        
    def start(self):
        self.reactor.listenUDP(self.port, self.transport, interface=self.interface)

    def send(self, node_id, message):
        self.client.send(node_id, message)
