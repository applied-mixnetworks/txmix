# -*- coding: utf-8 -*-

import pytest
import os
import binascii
from twisted.internet import reactor, defer
from sphinxmixcrypto import SphinxParams, PacketReplayCacheDict, SphinxLioness
from sphinxmixcrypto import add_padding, SECURITY_PARAMETER, SphinxPacket, SphinxBody

from txmix import OnionTransportFactory, ThresholdMixNode
from txmix.client import MixClient, RandomRouteFactory

from test_txmix import generate_node_id, generate_node_keypair, ChachaNoiseReader, SphinxNodeKeyState, DummyPKI


def create_transport_factory(receive_size, tor_control_tcp_port):
    tor_control_unix_socket = ""
    tor_control_tcp_host = "127.0.0.1"
    onion_unix_socket = ""
    onion_tcp_interface_ip = "127.0.0.1"
    transport_factory = OnionTransportFactory(reactor,
                                              receive_size,
                                              tor_control_unix_socket,
                                              tor_control_tcp_host,
                                              int(tor_control_tcp_port),
                                              onion_unix_socket,
                                              onion_tcp_interface_ip)
    return transport_factory


@pytest.inlineCallbacks
def test_onion_mix():
    """
    hello, actually i'm more of an integration test than a unit test.
    """

    chutney_control_port = os.environ.get('CHUTNEY_CONTROL_PORT')
    if chutney_control_port is None:
        print "CHUTNEY_CONTROL_PORT not set, aborting test"
        return

    params = SphinxParams(max_hops=5, payload_size=1024)
    # XXX sphinx_packet_size = params.get_sphinx_forward_size()
    sphinx_packet_size = reduce(lambda a, b: a + b, params.get_dimensions())
    transport_factory = create_transport_factory(sphinx_packet_size, chutney_control_port)
    pki = DummyPKI()
    rand_reader = ChachaNoiseReader("4704aff4bc2aaaa3fd187d52913a203aba4e19f6e7b491bda8c8e67daa8daa67")
    threshold_count = 10
    max_delay = 10
    mixes = []
    for mix_num in range(5):
        print "building mix %s" % mix_num
        node_id = generate_node_id(rand_reader)
        replay_cache = PacketReplayCacheDict()
        public_key, private_key = generate_node_keypair(rand_reader)
        key_state = SphinxNodeKeyState(public_key, private_key)
        transport = yield transport_factory.build_transport()
        mix = ThresholdMixNode(threshold_count, node_id, replay_cache, key_state, params, pki, transport, reactor, max_delay)
        yield mix.start()
        mixes.append(mix)

    print "\n"
    for mix_id in pki.identities():
        addr = pki.get_mix_addr("onion", mix_id)
        print "mix_id %s addr %r" % (binascii.hexlify(mix_id), addr)

    route_factory = RandomRouteFactory(params, pki, rand_reader)

    # setup alice's client
    client_receive_size = 1024 + 16
    client_transport_factory = create_transport_factory(client_receive_size, chutney_control_port)
    alice_transport = yield client_transport_factory.build_transport()
    alice_client_id = b"alice client"
    alice_received_d = defer.Deferred()

    def alice_client_received(packet):
        print "alice_client_received: %s" % packet.payload
        alice_received_d.callback(None)

    alice_client = MixClient(params, pki, alice_client_id, rand_reader, alice_transport, alice_client_received, route_factory)
    yield alice_client.start()
    print "alice's client started"

    # setup bob's client
    bob_transport = yield client_transport_factory.build_transport()
    bob_client_id = b"bob client"
    bob_received_d = defer.Deferred()

    def bob_client_received(packet):
        print "bob_client_received: %s" % packet.payload
        bob_received_d.callback(None)

    bob_client = MixClient(params, pki, bob_client_id, rand_reader, bob_transport, bob_client_received, route_factory)
    yield bob_client.start()
    print "bob's client started"

    cascade_route = route_factory.build_route(pki.identities()[0])

    for message_num in range(threshold_count + 2):
        print "Bob sending message %s to Alice" % message_num
        message = b"hello Alice, this is Bob. message %s" % message_num

        # XXX create_nym method should be renamed to create_reply_block in
        # a future version of sphinxmixcrypto
        reply_block = alice_client.protocol.sphinx_client.create_nym(cascade_route, pki)

        # XXX hello, this API is terrible and needs to be fixed
        n0, header0, ktilde = reply_block
        block_cipher = SphinxLioness()
        key = block_cipher.create_block_cipher_key(ktilde)
        block = add_padding((b"\x00" * SECURITY_PARAMETER) + message, params.payload_size)
        body = block_cipher.encrypt(key, block)
        sphinx_packet = SphinxPacket(header0, SphinxBody(body))

        # XXX srsly we should not be reaching into the client like this. terrible.
        # fix me
        dest_addr = pki.get_mix_addr("onion", n0)
        yield bob_client.protocol.transport.send(dest_addr, sphinx_packet.get_raw_bytes())

    for message_num in range(threshold_count):
        yield alice_received_d
        alice_received_d = defer.Deferred()
