
from __future__ import print_function

from zope.interface import implementer
from twisted.internet.protocol import DatagramProtocol

from txmix import IMixClientTransport


@implementer(IMixClientTransport)
class UDPClientTransport(DatagramProtocol):
    """
    implements the IMixClientTransport interface
    """
    name = "udp"

    def __init__(self, interface, port):
        self.interface = interface
        self.port = port
        self.received_callback = None

    def setClient(self, client):
        """
        sets the client class as the consumer of raw mixnet messages
        """
        self.received_callback = client.received

    def start(self):
        self.reactor.listenUDP(self.port, self, interface=self.interface)

    def send(self, addr, message):
        """
        send message to addr
        where addr is a 2-tuple of type: (ip address, UDP port)
        """
        self.transport.write(message, addr)

    def received(self, message):
        """
        i am called by the twisted reactor when our transport receives a UDP packet
        """
        self.received_callback(message)
