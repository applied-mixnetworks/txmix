
from __future__ import print_function

import attr
from zope.interface import implementer
from twisted.internet.interfaces import IReactorUDP
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import defer

from txmix import IMixTransport


@implementer(IMixTransport)
@attr.s()
class UDPTransport(DatagramProtocol, object):
    """
    implements the IMixTransport interface
    """
    name = "udp"
    reactor = attr.ib(validator=attr.validators.provides(IReactorUDP))
    addr = attr.ib(validator=attr.validators.instance_of(tuple))

    def register_protocol(self, protocol):
        # XXX todo: assert that protocol provides the appropriate interface
        self.protocol = protocol

    def start(self):
        """
        make this transport begin listening on the specified interface and UDP port
        interface must be an IP address
        """
        interface, port = self.addr
        self.reactor.listenUDP(port, self, interface=interface)
        return defer.succeed(None)

    def send(self, addr, message):
        """
        send message to addr
        where addr is a 2-tuple of type: (ip address, UDP port)
        """
        self.transport.write(message, addr)
        return defer.succeed(None)

    def datagramReceived(self, datagram, addr):
        """
        i am called by the twisted reactor when our transport receives a UDP packet
        """
        self.protocol.received(datagram)
