
from __future__ import print_function

from sphinxmixcrypto import sphinx_packet_unwrap, GroupCurve25519
from txmix.common import DEFAULT_CRYPTO_PARAMETERS, sphinx_packet_encode, sphinx_packet_decode


class NodeFactory(object):
    """
    Factory class for creating mixes.
    """
    def __init__(self, pki, params=None):
        self.pki = pki
        if params is None:
            self.params = DEFAULT_CRYPTO_PARAMETERS
        else:
            self.params = params

    def build_protocol(self, replay_cache, key_state, transport, addr):
        node_protocol = NodeProtocol(replay_cache, key_state, self.params, self.pki, transport)
        transport.start(addr, node_protocol)
        return node_protocol


class NodeProtocol(object):
    """
    i am a mix net node protocol responsible for decryption
    and mixing.
    """

    def __init__(self, replay_cache, key_state, params, pki, transport):
        self.replay_cache = replay_cache
        self.key_state = key_state
        self.params = params
        self.pki = pki
        self.transport = transport

    def make_connection(self, transport):
        self.transport = transport

    def sphinx_packet_received(self, raw_sphinx_packet):
        """
        i receive a raw_packet, decode it and unwrap/decrypt it
        and return the results
        """
        sphinx_packet = sphinx_packet_decode(self.params, raw_sphinx_packet)
        return sphinx_packet_unwrap(self.params, self.replay_cache, self.key_state, sphinx_packet)

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


class ThresholdMix(object):

    def process_unwrapped_message(self, message_result):
        if message_result.tuple_next_hop:
            nextHop, header, delta = message_result.tuple_next_hop
            alpha, beta, gamma = header
            sphinx_message = {
                "alpha": alpha,
                "beta": beta,
                "gamma": gamma,
                "delta": delta,
            }
            #  self.send_to_mix(nextHop, sphinx_message)
        elif message_result.tuple_exit_hop:
            destination, message = message_result.tuple_exit_hop
            sphinx_message = {
                "alpha": None,
                "beta": None,
                "gamma": None,
                "delta": message,
            }
            #  self.send_to_exit_mix(destination, sphinx_message)
        else:
            #  XXX
            pass

