
import attr
import types
import random

from twisted.internet.interfaces import IReactorCore
from twisted.internet import reactor

from sphinxmixcrypto import sphinx_packet_unwrap, SphinxParams, SphinxPacket
from sphinxmixcrypto import IPacketReplayCache, IKeyState, IMixPKI

from txmix.interfaces import IMixTransport


@attr.s
class NodeProtocol(object):
    """
    i am a mix net node protocol responsible for decryption and
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
        """
        assert IMixTransport.providedBy(transport)
        transport.register_protocol(self)
        transport.start()
        self.transport = transport

    def received(self, raw_sphinx_packet):
        """
        receive a raw_packet, decode it and unwrap/decrypt it
        and return the results
        """
        sphinx_packet = SphinxPacket.from_raw_bytes(self.params, raw_sphinx_packet)
        unwrapped_packet = sphinx_packet_unwrap(self.params, self.replay_cache, self.key_state, sphinx_packet)
        self.packet_received_handler(unwrapped_packet)

    def sphinx_packet_send(self, mix_id, sphinx_packet):
        """
        given a SphinxPacket object I shall encode it into
        a raw packet and send it to the mix with mix_id
        """
        addr = self.pki.get_mix_addr(self.transport.name, mix_id)
        raw_sphinx_packet = sphinx_packet.get_raw_bytes()
        self.transport.send(addr, raw_sphinx_packet)


def is_16bytes(instance, attribute, value):
    """
    validator for node_id which should be a 16 byte value
    """
    if not isinstance(value, bytes) or len(value) != 16:
        raise ValueError("must be 16 byte value")


@attr.s
class ThresholdMixNode(object):
    """
    i am a threshold mix node
    """

    threshold_count = attr.ib(validator=attr.validators.instance_of(int))
    node_id = attr.ib(validator=is_16bytes)
    replay_cache = attr.ib(validator=attr.validators.provides(IPacketReplayCache))
    key_state = attr.ib(validator=attr.validators.provides(IKeyState))
    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    transport = attr.ib(validator=attr.validators.provides(IMixTransport))
    reactor = attr.ib(validator=attr.validators.provides(IReactorCore), default=reactor)
    _batch = attr.ib(init=False, default=[])  # list of 2-tuples [(destination, sphinx_packet)]
    _max_delay = attr.ib(init=False, default=600)

    def start(self):
        """
        start the mix
        """
        self.protocol = NodeProtocol(self.replay_cache,
                                     self.key_state,
                                     self.params,
                                     self.pki,
                                     packet_received_handler=lambda x: self.packet_received(x))
        self.protocol.make_connection(self.transport)
        self.pki.set(self.node_id, self.key_state.get_public_key(), self.protocol.transport.addr)

    def packet_received(self, result):
        """
        receive the unwrapped packet and append it to the batch.
        if the threshold is reached then we shuffle the batch
        and send the batch out after a random delay.
        """
        if result.next_hop:
            self._batch.append(result.next_hop)  # [(destination, sphinx_packet)]
            if len(self._batch) >= self.threshold_count:
                released = self._batch
                self._batch = []
                random.shuffle(released)
                delay = random.SystemRandom.randint(0, self._max_delay)
                self.reactor.callLater(delay, self.batch_send, released)

    def batch_send(self, batch):
        """
        send a batch of mix net messages to their respective destinations
        """
        for destination, message in batch:
            self.protocol.sphinx_packet_send(destination, message)
