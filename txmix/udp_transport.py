
from __future__ import print_function

from zope.interface import implementer
from twisted.internet.protocol import DatagramProtocol

from txmix import IMixTransport


@implementer(IMixTransport)
class UDPTransport(DatagramProtocol):
    """
    implements the IMixClientTransport interface
    """
    name = "udp"

    def __init__(self):
        self.received_callback = None

    def setProtocol(self, nodeProtocol):
        """
        sets the client class as the consumer of raw mixnet messages
        """
        self.received_callback = nodeProtocol.messageReceived

    def listen(self, reactor, addr):
        """
        make this transport begin listening on the specified interface and UDP port
        interface must be an IP address
        """
        assert self.received_callback is not None
        self.reactor = reactor
        interface, port = addr
        self.reactor.listenUDP(port, self, interface=interface)

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
