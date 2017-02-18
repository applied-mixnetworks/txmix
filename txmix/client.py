
import attr
import types
import binascii

from eliot import start_action
from eliot.twisted import DeferredContext

from zope.interface import implementer

from sphinxmixcrypto import SphinxParams, SphinxPacket, ReplyBlock
from sphinxmixcrypto import IMixPKI, IReader, SECURITY_PARAMETER

from txmix import IMixTransport, IRouteFactory


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
        self._decryption_tokens = {}
        transport.register_protocol(self)
        d = transport.start()
        self.transport = transport
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
        message = self._decryption_tokens[message_id].decrypt(ciphertext)
        self.packet_received_handler(message)

    def send(self, route, message):
        """
        send a wrapped inside a forward sphinx packet
        """
        first_hop_addr = self.pki.get_mix_addr(self.transport.name, route[0])
        sphinx_packet = SphinxPacket.forward_message(self.params, route, self.pki, route[-1], message, self.rand_reader)
        raw_sphinx_packet = sphinx_packet.get_raw_bytes()
        return self.transport.send(first_hop_addr, raw_sphinx_packet)

    def create_reply_block(self, route):
        """
        given a route and a client ID
        """
        message_id = self.rand_reader.read(SECURITY_PARAMETER)
        decryption_token, reply_block = ReplyBlock.compose_reply_block(message_id,
                                                                       self.params,
                                                                       route,
                                                                       self.pki,
                                                                       self.client_id,
                                                                       self.rand_reader)
        self._decryption_tokens[decryption_token.message_id] = decryption_token
        return reply_block


@implementer(IRouteFactory)
@attr.s
class RandomRouteFactory(object):
    """
    I create random routes.
    """
    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    rand_reader = attr.ib(validator=attr.validators.provides(IReader))

    def build_route(self):
        """
        return a new random route
        """
        #  XXX todo: assert destination type
        mixes = self.pki.identities()
        assert len(mixes) >= self.params.max_hops
        nodeids = [(self.rand_reader.read(8), x) for x in mixes]
        nodeids.sort(key=lambda x: x[0])
        return [x[1] for x in nodeids[:self.params.max_hops]]


@implementer(IRouteFactory)
@attr.s
class CascadeRouteFactory(object):
    route = attr.ib(validator=attr.validators.instance_of(list))

    def build_route(self):
        return self.route


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
        self.pki.set_client_addr("onion", self.protocol.client_id, self.transport.addr)
        return d

    def message_received(self, message):
        """
        receive a message
        """
        action = start_action(
            action_type=u"mix client:message received",
            client_id=binascii.hexlify(self.client_id),
        )
        with action.context():
            self.message_received_handler(message)

    def send(self, destination, message):
        """
        send a message to the given destination
        returns a deferred
        """
        action = start_action(
            action_type=u"mix client:message send",
            client_id=binascii.hexlify(self.client_id),
        )
        with action.context():
            d = self.protocol.send(self.route_factory.build_route(), message)
            return DeferredContext(d).addActionFinish()

    def create_reply_block(self):
        """
        return a new reply block for the given destination
        """
        return self.protocol.create_reply_block(self.route_factory.build_route())

    def reply(self, reply_block, message):
        """
        compose a reply with a payload of `message` using the given `reply_block`
        """
        assert isinstance(reply_block, ReplyBlock)
        sphinx_packet = reply_block.compose_forward_message(self.params, message)
        dest_addr = self.pki.get_mix_addr("onion", reply_block.destination)
        return self.protocol.transport.send(dest_addr, sphinx_packet.get_raw_bytes())
