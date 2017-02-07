
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
    packet_receive_handler = attr.ib(validator=attr.validators.instance_of(types.FunctionType))

    def make_connection(self, transport):
        assert IMixTransport.providedBy(transport)
        transport.register_protocol(self)
        transport.start()
        self.transport = transport
        self.sphinx_client = SphinxClient(self.params, self.client_id, self.rand_reader)

    def received(self, packet):
        message_id = packet[:16]
        payload = packet[16:]
        assert len(payload) == self.params.payload_size
        self.message_received(message_id, payload)

    def message_received(self, message_id, ciphertext):
        message = self.sphinx_client.decrypt(message_id, ciphertext)
        self.packet_receive_handler(message)

    def send(self, route, message):
        first_hop_addr = self.pki.get_mix_addr(self.transport.name, route[0])
        alpha, beta, gamma, delta = create_forward_message(self.params, route, self.pki, route[-1], message, self.rand_reader)
        serialized_sphinx_packet = sphinx_packet_encode(self.params, alpha, beta, gamma, delta)
        self.transport.send(first_hop_addr, serialized_sphinx_packet)


@attr.s
class SprayMixClient(object):
    """
    i am a client of the mixnet used for testing
    """

    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    client_id = attr.ib(validator=attr.validators.instance_of(bytes))
    rand_reader = attr.ib(validator=attr.validators.provides(IReader))
    transport = attr.ib(validator=attr.validators.provides(IMixTransport))

    def start(self):
        self.protocol = ClientProtocol(self.params, self.pki, self.client_id, self.rand_reader,
                                       packet_receive_handler=lambda x: self.message_received(x))
        self.protocol.make_connection(self.transport)

    def message_receive(self, message):
        pass  # XXX do something with the message
