
import attr
import types

from sphinxmixcrypto import SphinxParams, SphinxClient, create_forward_message, sphinx_packet_encode
from sphinxmixcrypto import IMixPKI, IReader

from txmix import IMixTransport


@attr.s
class ClientProtocol(object):
    """
    I am a sphinx mix network client protocol which
    means I have a producer/consumer relationship with
    a sphinx mix network client transport.
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
        transport.start()
        self.transport = transport
        self.sphinx_client = SphinxClient(self.params, self.client_id, self.rand_reader)

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
        alpha, beta, gamma, delta = create_forward_message(self.params, route, self.pki, route[-1], message, self.rand_reader)
        serialized_sphinx_packet = sphinx_packet_encode(self.params, alpha, beta, gamma, delta)
        self.transport.send(first_hop_addr, serialized_sphinx_packet)


@attr.s
class MixClient(object):
    """
    i am a client of the mixnet
    """

    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    client_id = attr.ib(validator=attr.validators.instance_of(bytes))
    rand_reader = attr.ib(validator=attr.validators.provides(IReader))
    transport = attr.ib(validator=attr.validators.provides(IMixTransport))
    message_received_handler = attr.ib(validator=attr.validators.instance_of(types.FunctionType))

    def start(self):
        """
        start the mix client
        """
        self.protocol = ClientProtocol(self.params, self.pki, self.client_id, self.rand_reader,
                                       packet_received_handler=lambda x: self.message_received(x))
        self.protocol.make_connection(self.transport)

    def message_received(self, message):
        """
        receive a message
        """
        self.message_received_handler(message)

    def send(self, destination, message):
        """
        send a message to the given destination
        """

        route = self._generate_route(destination)
        self.protocol.send(route, message)

    def _generate_route(self, destination):
        """
        generate a new route
        """
        mixes = self.pki.identities()
        mixes.remove(destination)
        nodeids = [(self.rand_reader.read(8), x) for x in mixes]
        nodeids.sort(key=lambda x: x[0])
        return [x[1] for x in nodeids[:nu]] + [destination]
