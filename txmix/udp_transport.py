
from __future__ import print_function

from zope.interface import implementer
from twisted.internet.protocol import DatagramProtocol

from txmix import IMixClientTransport


@implementer(IMixClientTransport)
class UDPClientTransport(DatagramProtocol):
    """
    implements the IMixClient interface u
    """

    def __init__(self, received_callback):
        self.received_callback = received_callback

    def send(self, addr, message):
        """
        send message to addr
        where addr is a 2-tuple of type: (ip address, UDP port)
        """
        self.transport.write(message, addr)

    def received(self, message):
        self.received_callback(message)
