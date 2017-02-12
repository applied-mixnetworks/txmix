
import attr
import types

from sphinxmixcrypto import SphinxParams, SphinxClient, SphinxPacket
from sphinxmixcrypto import IMixPKI, IReader

from txmix import IMixTransport, IRouteFactory
from zope.interface import implementer


@attr.s
class ClientProtocol(object):
    """
    I am a sphinx mix network client protocol which means I act as a
    proxy between the client and the transport.  I decrypt messages
    before proxying them.
    """

    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    client_id = attr.ib(validator=attr.validators.instance_of(bytes))
    rand_reader = attr.ib(validator=attr.validators.provides(IReader))
    packet_received_handler = attr.ib(validator=attr.validators.instance_of(types.FunctionType))

    def make_connection(self, transport):
        """
        connect this protocol with the transport
        and start the transport
        """
        assert IMixTransport.providedBy(transport)
        transport.register_protocol(self)
        d = transport.start()
        self.transport = transport
        self.sphinx_client = SphinxClient(self.params, self.client_id, self.rand_reader)
        return d

    def received(self, packet):
        """
        receive a client packet, a message ID
        and an encrypted payload
        """
        message_id = packet[:16]
        payload = packet[16:]
        assert len(payload) == self.params.payload_size
        self.message_received(message_id, payload)

    def message_received(self, message_id, ciphertext):
        """
        decrypt the message and pass it to the message handler
        """
        message = self.sphinx_client.decrypt(message_id, ciphertext)
        self.packet_receive_handler(message)

    def send(self, route, message):
        """
        send a wrapped inside a forward sphinx packet
        """
        first_hop_addr = self.pki.get_mix_addr(self.transport.name, route[0])
        sphinx_packet = SphinxPacket.forward_message(self.params, route, self.pki, route[-1], message, self.rand_reader)
        raw_sphinx_packet = sphinx_packet.get_raw_bytes()
        self.transport.send(first_hop_addr, raw_sphinx_packet)


@implementer(IRouteFactory)
@attr.s
class RandomRouteFactory(object):
    """
    I create random routes.
    """
    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    rand_reader = attr.ib(validator=attr.validators.provides(IReader))

    def build_route(self, destination):
        """
        return a new random route
        """
        #  XXX todo: assert destination type
        mixes = self.pki.identities()
        assert len(mixes) >= self.params.max_hops
        mixes.remove(destination)
        nodeids = [(self.rand_reader.read(8), x) for x in mixes]
        nodeids.sort(key=lambda x: x[0])
        return [x[1] for x in nodeids[:self.params.max_hops - 1]] + [destination]


@attr.s
class MixClient(object):
    """
    i am a client of the mixnet.
    """

    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    client_id = attr.ib(validator=attr.validators.instance_of(bytes))
    rand_reader = attr.ib(validator=attr.validators.provides(IReader))
    transport = attr.ib(validator=attr.validators.provides(IMixTransport))
    message_received_handler = attr.ib(validator=attr.validators.instance_of(types.FunctionType))
    route_factory = attr.ib(validator=attr.validators.provides(IRouteFactory))

    def start(self):
        """
        start the mix client
        """
        self.protocol = ClientProtocol(self.params, self.pki, self.client_id, self.rand_reader,
                                       packet_received_handler=lambda x: self.message_received(x))
        d = self.protocol.make_connection(self.transport)
        return d

    def message_received(self, message):
        """
        receive a message
        """
        self.message_received_handler(message)

    def send(self, destination, message):
        """
        send a message to the given destination
        returns a deferred
        """
        return self.protocol.send(self.route_factory.build_route(destination), message)
