
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

import attr
from zope.interface import implementer
from twisted.internet.protocol import Factory
from twisted.internet import endpoints
from twisted.internet.interfaces import IReactorCore
from twisted.internet.protocol import Protocol
from twisted.internet import defer
from twisted.internet.error import ConnectionDone
import txtorcon
from txtorcon import ITorControlProtocol, EphemeralHiddenService

from sphinxmixcrypto import SphinxParams
from txmix import IMixTransport


@attr.s()
class OnionTransportFactory(object):

    reactor = attr.ib(validator=attr.validators.provides(IReactorCore))
    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    tor_control_unix_socket = attr.ib(validator=attr.validators.instance_of(str), default=None)
    tor_control_tcp_host = attr.ib(validator=attr.validators.instance_of(str), default=None)
    tor_control_tcp_port = attr.ib(validator=attr.validators.instance_of(int), default=None)
    onion_unix_socket = attr.ib(validator=attr.validators.instance_of(str), default=None)
    onion_tcp_interface_ip = attr.ib(validator=attr.validators.instance_of(str), default=None)
    onion_service_port = 999

    @defer.inlineCallbacks
    def build_transport(self):
        if len(self.tor_control_unix_socket) == 0:
            assert len(self.onion_tcp_interface_ip) != 0
            control_socket_endpoint = "tcp:%s:%s" % (self.tor_control_tcp_host, self.tor_control_tcp_port)
        else:
            control_socket_endpoint = "unix:%s" % self.tor_control_unix_socket
        endpoint = endpoints.clientFromString(self.reactor, control_socket_endpoint.encode('utf-8'))
        tor_control_protocol = yield txtorcon.build_tor_connection(endpoint, build_state=False)
        onion_tcp_port = 0
        if len(self.onion_unix_socket) == 0:
            onion_tcp_port = yield txtorcon.util.available_tcp_port(self.reactor)
            hs = EphemeralHiddenService(["%s %s:%s" % (self.onion_service_port, self.onion_tcp_interface_ip, onion_tcp_port)])
        else:
            hs = EphemeralHiddenService(["%s unix:%s" % (self.onion_service_port, self.onion_unix_socket)])
        yield hs.add_to_tor(tor_control_protocol)
        alpha, beta, gamma, delta = self.params.get_dimensions()
        sphinx_packet_size = alpha + beta + gamma + delta
        transport = OnionTransport(self.reactor,
                                   sphinx_packet_size,
                                   tor_control_protocol,
                                   onion_host=hs.hostname,
                                   onion_port=self.onion_service_port,
                                   onion_key=hs.private_key,
                                   onion_tcp_interface_ip=self.onion_tcp_interface_ip,
                                   onion_tcp_port=onion_tcp_port,
                                   )
        yield hs.remove_from_tor(tor_control_protocol)
        defer.returnValue(transport)


class OnionTransportConnectionFailure(Exception):
    """
    onion transport connection failure exception
    """


@implementer(IMixTransport)
@attr.s()
class OnionTransport(object, Protocol):
    """
    implements the IMixTransport interface using Tor as the transport.
    A Tor onion service is used for receiving messages.
    """
    name = "onion"
    buffer = []

    reactor = attr.ib(validator=attr.validators.provides(IReactorCore))
    sphinx_packet_size = attr.ib(validator=attr.validators.instance_of(int))
    tor_control_protocol = attr.ib(validator=attr.validators.provides(ITorControlProtocol))

    onion_host = attr.ib(validator=attr.validators.instance_of(str))
    onion_port = attr.ib(validator=attr.validators.instance_of(int))
    onion_key = attr.ib(validator=attr.validators.instance_of(bytes))

    # This transport can be configured to either use a tcp listener or
    # a unix domain socket listener for receiving inbound Tor onion service
    # connections. Some security sandboxing environments might enforce using
    # unix domain sockets.
    onion_unix_socket = attr.ib(validator=attr.validators.instance_of(str), default="")
    onion_tcp_interface_ip = attr.ib(validator=attr.validators.instance_of(str), default="")
    onion_tcp_port = attr.ib(validator=attr.validators.instance_of(int), default=0)

    @property
    def addr(self):
        return self.onion_host, self.onion_port

    def register_protocol(self, protocol):
        # XXX todo: assert that protocol provides the appropriate interface
        self.protocol = protocol

    def start(self):
        """
        make this transport begin listening on the specified interface and UDP port
        interface must be an IP address
        """
        hs_strings = []
        if len(self.onion_unix_socket) == 0:
            local_socket_endpoint_desc = "tcp:interface=%s:%s" % (self.onion_tcp_interface_ip, self.onion_tcp_port)
        else:
            local_socket_endpoint_desc = "unix:%s" % self.onion_unix_socket
        onion_service_endpoint = endpoints.serverFromString(self.reactor, local_socket_endpoint_desc)
        d = onion_service_endpoint.listen(Factory.forProtocol(self))

        def got_socket(result):
            if len(self.onion_unix_socket) == 0:
                hs_strings.append("%s %s:%s" % (self.onion_port, self.onion_tcp_interface_ip, self.onion_tcp_port))
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
        tor_endpoint = endpoints.clientFromString("tor:%s:%s" % addr)
        send_message_protocol = Protocol()

        class OneShotSendProtocol(Protocol):
            """
            """
        send_message_protocol = OneShotSendProtocol()
        d = endpoints.connectProtocol(tor_endpoint, send_message_protocol)

        def is_connected(protocol):
            protocol.transport.write(message)
            protocol.loseConnection()

        d.addCallback(is_connected)
        return d

    # Protocol parent method overwriting

    def dataReceived(self, data):
        if len(data) == self.sphinx_packet_size and len(self.buffer) == 0:
            self.protocol.received(data)
            return

        if len(data) < self.sphinx_packet_size:
            self.buffer.append(data)
        elif len(data) > self.sphinx_packet_size:
            self.buffer.append(data[self.sphinx_packet_size:])
            self.protocol.received(data[:self.sphinx_packet_size])
            return

    def connectionLost(self, reason):
        """
        Called when the connection is shut down.
        """
        if not isinstance(reason, ConnectionDone):
            raise OnionTransportConnectionFailure()
