
"""
I am a txmix transport using tor circuits and tor onion services.
This transport has the following properties which the UDP
transport does not:

 1. reliability
 2. forward secrecy
 3. NAT penetration
 4. hides client location from mix node interaction
"""

import attr

from eliot import start_action, Message
from eliot.twisted import DeferredContext

from zope.interface import implementer

from twisted.internet.protocol import Factory
from twisted.internet import endpoints
from twisted.internet.interfaces import IReactorCore
from twisted.internet.protocol import Protocol
from twisted.internet import defer
from twisted.internet.error import ConnectionDone

import txtorcon

from txmix import IMixTransport
from .buffer import Buffer


@attr.s()
class OnionTransportFactory(object):

    reactor = attr.ib(validator=attr.validators.provides(IReactorCore))
    datagram_receive_size = attr.ib(validator=attr.validators.instance_of(int))
    tor_control_unix_socket = attr.ib(validator=attr.validators.instance_of(str), default="")
    tor_control_tcp_host = attr.ib(validator=attr.validators.instance_of(str), default="")
    tor_control_tcp_port = attr.ib(validator=attr.validators.instance_of(int), default=0)
    onion_unix_socket = attr.ib(validator=attr.validators.instance_of(str), default="")
    onion_tcp_interface_ip = attr.ib(validator=attr.validators.instance_of(str), default="")
    onion_service_port = 999

    def build_transport(self):
        action = start_action(
            action_type=u"onion-transport-factory:build-transport",
        )
        with action.context():
            d = self.do_build_transport()
            return DeferredContext(d).addActionFinish()

    @defer.inlineCallbacks
    def do_build_transport(self):
        if len(self.tor_control_unix_socket) == 0:
            assert len(self.onion_tcp_interface_ip) != 0
            tor_controller_endpoint_desc = "tcp:%s:%s" % (self.tor_control_tcp_host, self.tor_control_tcp_port)
        else:
            tor_controller_endpoint_desc = "unix:%s" % self.tor_control_unix_socket
        tor_controller_endpoint = endpoints.clientFromString(self.reactor, tor_controller_endpoint_desc)
        tor = yield txtorcon.connect(self.reactor, control_endpoint=tor_controller_endpoint)
        onion_tcp_port = 0
        if len(self.onion_unix_socket) == 0:
            onion_tcp_port = yield txtorcon.util.available_tcp_port(self.reactor)
            hs = txtorcon.EphemeralHiddenService(["%s %s:%s" % (self.onion_service_port, self.onion_tcp_interface_ip, onion_tcp_port)])
        else:
            hs = txtorcon.EphemeralHiddenService(["%s unix:%s" % (self.onion_service_port, self.onion_unix_socket)])
        yield hs.add_to_tor(tor.protocol)
        transport = OnionTransport(self.reactor,
                                   self.datagram_receive_size,
                                   tor,
                                   onion_host=hs.hostname.encode('utf-8'),
                                   onion_port=self.onion_service_port,
                                   onion_key=hs.private_key.encode('utf-8'),
                                   onion_tcp_interface_ip=self.onion_tcp_interface_ip,
                                   onion_tcp_port=onion_tcp_port)
        yield hs.remove_from_tor(tor.protocol)
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
    receive_buffer = Buffer()

    reactor = attr.ib(validator=attr.validators.provides(IReactorCore))
    datagram_receive_size = attr.ib(validator=attr.validators.instance_of(int))
    tor = attr.ib(validator=attr.validators.instance_of(txtorcon.Tor))

    onion_host = attr.ib(validator=attr.validators.instance_of(str))
    onion_port = attr.ib(validator=attr.validators.instance_of(int))
    onion_key = attr.ib(validator=attr.validators.instance_of(bytes))

    # This transport can be configured to either use a tcp listener or
    # a unix domain socket listener for receiving inbound Tor onion
    # service connections.
    onion_unix_socket = attr.ib(validator=attr.validators.instance_of(str), default="")
    onion_tcp_interface_ip = attr.ib(validator=attr.validators.instance_of(str), default="")
    onion_tcp_port = attr.ib(validator=attr.validators.instance_of(int), default=0)

    @property
    def addr(self):
        return self.onion_host, self.onion_port

    def register_protocol(self, protocol):
        # XXX todo: assert that protocol provides the appropriate interface
        self.mix_protocol = protocol

    def start(self):
        """
        start the transport, call do_start
        """
        action = start_action(
            action_type=u"onion-transport:start-onion-service",
            onion_host=self.onion_host,
            onion_port=self.onion_port,
        )
        with action.context():
            d = self.do_start()
            return DeferredContext(d).addActionFinish()

    @defer.inlineCallbacks
    def do_start(self):
        """
        make this transport begin listening on the specified interface and UDP port
        interface must be an IP address
        """

        # save a TorConfig so we can later use it to send messages
        self.torconfig = txtorcon.TorConfig(control=self.tor.protocol)
        yield self.torconfig.post_bootstrap

        hs_strings = []
        if len(self.onion_unix_socket) == 0:
            local_socket_endpoint_desc = "tcp:interface=%s:%s" % (self.onion_tcp_interface_ip, self.onion_tcp_port)
        else:
            local_socket_endpoint_desc = "unix:%s" % self.onion_unix_socket
        onion_service_endpoint = endpoints.serverFromString(self.reactor, local_socket_endpoint_desc)
        yield onion_service_endpoint.listen(Factory.forProtocol(lambda: self))

        if len(self.onion_unix_socket) == 0:
            hs_strings.append("%s %s:%s" % (self.onion_port, self.onion_tcp_interface_ip, self.onion_tcp_port))
        else:
            hs_strings.append("%s unix:%s" % (self.onion_port, self.onion_unix_socket))
        hs = txtorcon.torconfig.EphemeralHiddenService(hs_strings, key_blob_or_type=self.onion_key)
        yield hs.add_to_tor(self.tor.protocol)

    def send(self, addr, message):
        action = start_action(
            action_type=u"onion-transport:send",
            destination=addr,
            message_size=len(message),
        )
        with action.context():
            d = self.do_send(addr, message)
            return DeferredContext(d).addActionFinish()

    @defer.inlineCallbacks
    def do_send(self, addr, message):
        """
        send message to addr
        where addr is a 2-tuple of type: (onion host, onion port)
        """
        onion_host, onion_port = addr
        tor_endpoint = self.tor.stream_via(onion_host, onion_port)
        send_message_protocol = Protocol()
        self.remote_mix_protocol = yield endpoints.connectProtocol(tor_endpoint, send_message_protocol)
        self.remote_mix_protocol.transport.write(message)
        self.remote_mix_protocol.transport.loseConnection()

    # Protocol parent method overwriting

    def dataReceived(self, data):
        Message.log(event_type="onion transport data received", datagram_size=len(data))
        # no buffering
        if len(data) == self.datagram_receive_size and len(self.receive_buffer) == 0:
            self.mix_protocol.received(data)
            return

        # buffering
        self.receive_buffer.write(data)
        if len(self.receive_buffer) >= self.datagram_receive_size:
            drained_data = self.receive_buffer.read(self.datagram_receive_size)
            self.mix_protocol.received(drained_data)

    def connectionLost(self, reason):
        """
        Called when the connection is shut down.
        """
        if not reason.check(ConnectionDone):
            pass  # XXX todo: log an error
