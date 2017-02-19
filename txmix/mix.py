
import attr
import types
import random

from eliot import start_action
from eliot.twisted import DeferredContext

from twisted.internet.interfaces import IReactorCore
from twisted.internet import reactor, defer
from twisted.internet.task import deferLater

from sphinxmixcrypto import sphinx_packet_unwrap, SphinxParams, SphinxPacket
from sphinxmixcrypto import IPacketReplayCache, IKeyState, IMixPKI, UnwrappedMessage

from txmix.interfaces import IMixTransport
from txmix.utils import is_16bytes


@attr.s
class MixProtocol(object):
    """
    i am a mix net protocol responsible for decryption and
    message passing to my mix helper class.
    """

    replay_cache = attr.ib(validator=attr.validators.provides(IPacketReplayCache))
    key_state = attr.ib(validator=attr.validators.provides(IKeyState))
    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    packet_received_handler = attr.ib(validator=attr.validators.instance_of(types.FunctionType))

    def make_connection(self, transport):
        """
        connect this protocol with the transport
        and start the transport
        returns a deferred which fires when the
        transport is started
        """
        assert IMixTransport.providedBy(transport)
        transport.register_protocol(self)
        d = transport.start()
        self.transport = transport
        return d

    def received(self, raw_sphinx_packet):
        """
        receive a raw_packet, decode it and unwrap/decrypt it
        and return the results
        """
        action = start_action(
            action_type=u"mix packet unwrap",
        )
        with action.context():
            sphinx_packet = SphinxPacket.from_raw_bytes(self.params, raw_sphinx_packet)
            unwrapped_packet = sphinx_packet_unwrap(self.params, self.replay_cache, self.key_state, sphinx_packet)
        self.packet_received_handler(unwrapped_packet)

    def sphinx_packet_send(self, mix_id, sphinx_packet):
        """
        given a SphinxPacket object I shall encode it into
        a raw packet and send it to the mix with mix_id
        """
        return self.send(mix_id, sphinx_packet.get_raw_bytes())

    def send(self, destination, datagram):
        """
        given a SphinxPacket object I shall encode it into
        a raw packet and send it to the mix with mix_id
        """
        mix_addr = self.pki.get_mix_addr(self.transport.name, destination)
        return self.transport.send(mix_addr, datagram)

    @defer.inlineCallbacks
    def forward_to_client(self, client_id, message_id, client_message):
        """
        forward a ciphertext client message to a client
        """
        client_addr = self.pki.get_client_addr(self.transport.name, client_id)
        message = bytes(message_id) + bytes(client_message.delta)
        yield self.transport.send(client_addr, message)

    def packet_proxy(self, unwrapped_packet):
        """
        receive the unwrapped packet and append it to the batch.
        if the threshold is reached then we shuffle the batch
        and send the batch out after a random delay.
        """
        assert isinstance(unwrapped_packet, UnwrappedMessage)
        if unwrapped_packet.next_hop:
            action = start_action(
                action_type=u"proxy unwrapped packet to next hop",
            )
            with action.context():
                destination, sphinx_packet = unwrapped_packet.next_hop
                d = self.sphinx_packet_send(destination, sphinx_packet)
                DeferredContext(d).addActionFinish()
        elif unwrapped_packet.client_hop:
            action = start_action(
                action_type=u"proxy unwrapped packet to client hop",
            )
            with action.context():
                d = self.forward_to_client(*unwrapped_packet.client_hop)
                DeferredContext(d).addActionFinish()
        elif unwrapped_packet.exit_hop:
            raise UnimplementedError()
        else:
            raise InvalidSphinxPacketError()
        return d


class UnimplementedError(Exception):
    pass


class InvalidSphinxPacketError(Exception):
    pass


@attr.s
class ThresholdMixNode(object):
    """
    i am a threshold mix node. my design is vulnerable to n-1 or blending attacks.

    to learn more about these active attacks read this paper:
    "From a Trickle to a Flood: Active Attacks on Several Mix Types"
    by Andrei Serjantov, Roger Dingledine, and Paul Syverson
    https://www.freehaven.net/anonbib/cache/trickle02.pdf
    """
    threshold_count = attr.ib(validator=attr.validators.instance_of(int))
    node_id = attr.ib(validator=is_16bytes)
    replay_cache = attr.ib(validator=attr.validators.provides(IPacketReplayCache))
    key_state = attr.ib(validator=attr.validators.provides(IKeyState))
    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    transport = attr.ib(validator=attr.validators.provides(IMixTransport))
    reactor = attr.ib(validator=attr.validators.provides(IReactorCore), default=reactor)
    max_delay = attr.ib(default=600)

    def start(self):
        """
        start the mix
        """
        self._sys_rand = random.SystemRandom()
        self._batch = []  # message batch is a list of 2-tuples [(destination, sphinx_packet)]
        self._pending_batch_sends = set()
        self.protocol = MixProtocol(self.replay_cache,
                                    self.key_state,
                                    self.params,
                                    self.pki,
                                    packet_received_handler=lambda x: self.message_received(x))
        d = self.protocol.make_connection(self.transport)
        self.pki.set(self.node_id, self.key_state.get_public_key(), self.protocol.transport.addr)
        return d

    def message_received(self, unwrapped_message):
        """
        message is of type UnwrappedMessage
        """

        self._batch.append(unwrapped_message)  # [(destination, sphinx_packet)
        if len(self._batch) >= self.threshold_count:
            delay = self._sys_rand.randint(0, self.max_delay)
            action = start_action(
                action_type=u"send delayed message batch",
                delay=delay,
            )
            with action.context():
                released = self._batch
                self._batch = []
                random.shuffle(released)
                d = deferLater(self.reactor, delay, self.batch_send, released)
                DeferredContext(d).addActionFinish()
                self._pending_batch_sends.add(d)

                def _remove(res, d=d):
                    self._pending_batch_sends.remove(d)
                    return res

                d.addBoth(_remove)

    @defer.inlineCallbacks
    def batch_send(self, batch):
        """
        send a batch of mix net messages to their respective destinations
        """
        dl = []
        for unwrapped_message in batch:
            dl.append(self.protocol.packet_proxy(unwrapped_message))
        yield defer.DeferredList(dl)


@attr.s
class ContinuousTimeMixNode(object):
    """
    i am a continuous time mix. i am not vulnerable to the n-1 attacks.
    but my design has other problems such as not enforcing anonymity/mix set size.
    """
    node_id = attr.ib(validator=is_16bytes)
    max_delay = attr.ib(validator=attr.validators.instance_of(int))
    transport = attr.ib(validator=attr.validators.provides(IMixTransport))
    replay_cache = attr.ib(validator=attr.validators.provides(IPacketReplayCache))
    key_state = attr.ib(validator=attr.validators.provides(IKeyState))
    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    reactor = attr.ib(validator=attr.validators.provides(IReactorCore), default=reactor)

    def start(self):
        """
        start the mix
        """
        self._sys_rand = random.SystemRandom()
        self._pending_sends = set()
        self.protocol = MixProtocol(self.replay_cache,
                                    self.key_state,
                                    self.params,
                                    self.pki,
                                    packet_received_handler=lambda x: self.message_received(x))
        d = self.protocol.make_connection(self.transport)
        self.pki.set(self.node_id, self.key_state.get_public_key(), self.protocol.transport.addr)
        return d

    def message_received(self, unwrapped_message):
        """
        message is of type UnwrappedMessage
        """

        delay = self._sys_rand.randint(0, self.max_delay)
        action = start_action(
            action_type=u"send delayed message",
            delay=delay,
        )
        with action.context():
            d = deferLater(self.reactor, delay, self.protocol.packet_proxy, unwrapped_message)
            DeferredContext(d).addActionFinish()
            self._pending_sends.add(d)

            def _remove(res, d=d):
                self._pending_sends.remove(d)
                return res

            d.addBoth(_remove)
