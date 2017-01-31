
from __future__ import print_function

import attr
import types
from zope.interface.declarations import implementer

from sphinxmixcrypto import sphinx_packet_unwrap, GroupCurve25519, SphinxParams
from sphinxmixcrypto.common import IPacketReplayCache, IMixPrivateKey, IMixPKI

from txmix.common import DEFAULT_CRYPTO_PARAMETERS, sphinx_packet_encode, sphinx_packet_decode
from txmix.interfaces import IMixTransport


@attr.s(frozen=True)
class NodeFactory(object):
    """
    Factory class for creating mixes.
    """
    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    params = attr.ib(default=DEFAULT_CRYPTO_PARAMETERS, validator=attr.validators.instance_of(SphinxParams))

    def build_protocol(self, replay_cache, key_state, transport, addr):
        node_protocol = NodeProtocol(replay_cache, key_state, self.params, self.pki)
        node_protocol.make_connection(transport)
        return node_protocol


@attr.s
class NodeProtocol(object):
    """
    i am a mix net node protocol responsible for decryption and
    message passing to my mix helper class.
    """

    replay_cache = attr.ib(validator=attr.validators.provides(IPacketReplayCache))
    key_state = attr.ib(validator=attr.validators.provides(IMixPrivateKey))
    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    packet_receive_handler = attr.ib(validator=attr.validators.instance_of(types.FunctionType))

    def make_connection(self, transport):
        transport.register_protocol(self)
        transport.start()
        self.transport = transport

    def sphinx_packet_received(self, raw_sphinx_packet):
        """
        i receive a raw_packet, decode it and unwrap/decrypt it
        and return the results
        """
        sphinx_packet = sphinx_packet_decode(self.params, raw_sphinx_packet)
        unwrapped_packet = sphinx_packet_unwrap(self.params, self.replay_cache, self.key_state, sphinx_packet)
        self.packet_receive_handler(unwrapped_packet)

    def sphinx_packet_send(self, mix_id, sphinx_packet):
        """
        given a SphinxPacket object I shall encode it into
        a raw packet and send it to the mix with mix_id
        """
        raw_sphinx_packet = sphinx_packet_encode(
            sphinx_packet['alpha'],
            sphinx_packet['beta'],
            sphinx_packet['gamma'],
            sphinx_packet['delta'])

        addr = self.pki.get_mix_addr(self.transport.name, mix_id)
        self.transport.send(addr, raw_sphinx_packet)


def is_16bytes(instance, attribute, value):
    if not isinstance(value, bytes) or len(value) != 16:
        raise ValueError("must be 16 byte value")


@attr.s
class ThreshMixNode(object):
    """
    i am a thresh mix node
    """

    node_id = attr.ib(validator=is_16bytes)
    replay_cache = attr.ib(validator=attr.validators.provides(IPacketReplayCache))
    key_state = attr.ib(validator=attr.validators.provides(IMixPrivateKey))
    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    transport = attr.ib(validator=attr.validators.provides(IMixTransport))

    def start(self):
        self.protocol = NodeProtocol(self.replay_cache,
                                     self.key_state,
                                     self.params,
                                     self.pki,
                                     packet_receive_handler=lambda x: self.packet_received(x))
        self.protocol.make_connection(self.transport)
        self.pki.set(self.node_id, self.key_state.get_private_key(), self.protocol.transport.addr)

    def packet_received(self, unwrapped_packet):
        print("unwrapped_packet: %s" % unwrapped_packet) # XXX
