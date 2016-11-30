
from __future__ import print_function

from zope.interface import implementer
from twisted.internet.protocol import DatagramProtocol

from txmix import IMixTransport


@implementer(IMixTransport)
class UDPTransport(DatagramProtocol):
    """
    implements the IMixTransport interface
    """
    name = "udp"

    def __init__(self, reactor):
        self.reactor = reactor
        self.received_callback = None

    def start(self, addr, nodeProtocol):
        """
        make this transport begin listening on the specified interface and UDP port
        interface must be an IP address
        """
        self.received_callback = nodeProtocol.messageReceived
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
