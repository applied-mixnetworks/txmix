
"""
I am a txmix transport using tor circuits and tor onion services.
This transport has the following properties which the UDP
transport does not:

 1. reliability
 2. forward secrecy
 3. NAT penetration
 4. hides client location from mix node interaction

I'm only interested in the first three properties.  Property 4 is
already provided by the mix network, however we use the Tor transport
because it's convenient that it accomplishes the first three properties.
"""

from __future__ import print_function

import attr
from zope.interface import implementer
from twisted.internet import endpoints
from twisted.internet.protocol import Protocol
import txtorcon
from txtorcon import ITorControlProtocol

from txmix import IMixTransport


# XXX todo: write factory class


@implementer(IMixTransport)
@attr.s()
class OnionTransport(object, Protocol):
    """
    implements the IMixTransport interface using Tor as the transport.
    A Tor onion service is used for receiving messages.
    """
    name = "onion"
    addr = attr.ib(validator=attr.validators.instance_of(tuple))

    sphinx_packet_size = attr.ib(validator=attr.validators.instance_of(int))
    tor_control_protocol = attr.ib(validator=attr.validators.provides(ITorControlProtocol))

    # This transport can be configured to either use a tcp listener or
    # a unix domain socket listener for receiving inbound Tor onion service
    # connections. Some security sandboxing environments might enforce using
    # unix domain sockets.
    onion_unix_socket = attr.ib(validator=attr.validators.instance_of(str), default=None)
    onion_tcp_interface = attr.ib(validator=attr.validators.instance_of(str), default=None)
    onion_tcp_port = attr.ib(validator=attr.validators.instance_of(int), default=None)

    onion_host = attr.ib(validator=attr.validators.instance_of(str))
    onion_port = attr.ib(validator=attr.validators.instance_of(int))
    onion_key = attr.ib(validator=attr.validators.instance_of(bytes))

    def register_protocol(self, protocol):
        # XXX todo: assert that protocol provides the appropriate interface
        self.protocol = protocol

    def start(self):
        """
        make this transport begin listening on the specified interface and UDP port
        interface must be an IP address
        """
        onion, onion_port = self.addr
        assert onion_port > 1024
        hs_strings = []
        if self.onion_unix_socket is None:
            local_socket_endpoint = "unix:%s" % self.onion_unix_socket
        else:
            local_socket_endpoint = "tcp:%s:%s" % (self.onion_tcp_interface, self.onion_tcp_port)
        d = endpoints.connectProtocol(local_socket_endpoint, self)

        def got_socket(result):
            if self.onion_unix_socket is None:
                hs_strings.append("%s %s:%s" % (self.onion_port, self.onion_tcp_interface, self.onion_tcp_port))
            else:
                hs_strings.append("%s unix:%s" % (self.onion_port, self.onion_unix_socket))
            hs = txtorcon.torconfig.EphemeralHiddenService(hs_strings, key_blob_or_type=self.onion_key)
            d2 = hs.add_to_tor(self.tor_control_protocol)
            return d2
        d.addCallback(got_socket)
        return d

    def send(self, addr, message):
        """
        send message to addr
        where addr is a 2-tuple of type: (onion host, onion port)
        """
        endpoints.clientFromString("tor:%s:%s" % addr)

    # Protocol parent method overwriting

    def dataReceived(self, data):
        assert len(data) == self.sphinx_packet_size
        self.protocol.received(data)

    def connectionLost(self):
        """
        Called when the connection is shut down.
        """
        # XXX raise some kind of exception?
        pass
