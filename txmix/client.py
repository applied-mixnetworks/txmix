
import attr

from sphinxmixcrypto import SphinxParams, SphinxClient, create_forward_message, sphinx_packet_encode
from sphinxmixcrypto import IMixPKI, IReader
from txmix.common import DEFAULT_CRYPTO_PARAMETERS


@attr.s(frozen=True)
class ClientFactory(object):
    """
    Factory class for creating mix clients
    with parameterized transports, pki and sphinx crypto primitives
    """

    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    rand_reader = attr.ib(validator=attr.validators.provides(IReader))
    params = attr.ib(default=DEFAULT_CRYPTO_PARAMETERS, validator=attr.validators.instance_of(SphinxParams))

    def build_protocol(self, client_id, transport):
        client_protocol = ClientProtocol(self.params, self.pki, client_id, self.rand_reader, transport)
        transport.start()
        return client_protocol


class ClientProtocol(object):
    """
    I am a sphinx mix network client protocol which
    means I have a producer/consumer relationship with
    a sphinx mix network client transport.
    """
    def __init__(self, params, pki, client_id, rand_reader, transport):
        self.params = params
        self.sphinx_client = SphinxClient(params, client_id, rand_reader)
        self.rand_reader = rand_reader
        self.pki = pki
        self.transport = transport

    def message_received(self, nym_id, delta):
        unwrapped_message = self.sphinx_client.decrypt(nym_id, delta)
        self.protocol.messageReceived(unwrapped_message)

    def send(self, route, message):
        first_hop_addr = self.pki.get_mix_addr(self.transport.name, route[0])
        alpha, beta, gamma, delta = create_forward_message(self.params, route, self.pki, route[-1], message, self.rand_reader)
        serialized_sphinx_packet = sphinx_packet_encode(self.params, alpha, beta, gamma, delta)
        self.transport.send(first_hop_addr, serialized_sphinx_packet)
