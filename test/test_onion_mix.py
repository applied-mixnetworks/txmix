# -*- coding: utf-8 -*-

import pytest
import os
import binascii
from twisted.internet import reactor, defer
from sphinxmixcrypto import SphinxParams, PacketReplayCacheDict, SphinxLioness
from sphinxmixcrypto import add_padding, SECURITY_PARAMETER, SphinxPacket, SphinxBody

from txmix import OnionTransportFactory, ThresholdMixNode
from txmix.client import MixClient, RandomRouteFactory

from test_txmix import generate_node_id, generate_node_keypair, FixedNoiseReader, SphinxNodeKeyState, DummyPKI


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
    rand_reader = FixedNoiseReader("b5451d2eb2faf3f84bc4778ace6516e73e9da6c597e6f96f7e63c7ca6c9456018be9fd84883e4469a736c66fcaeceacf080fb06bc45859796707548c356c462594d1418b5349daf8fffe21a67affec10c0a2e3639c5bd9e8a9ddde5caf2e1db802995f54beae23305f2241c6517d301808c0946d5895bfd0d4b53d8ab2760e4ec8d4b2309eec239eedbab2c6ae532da37f3b633e256c6b551ed76321cc1f301d74a0a8a0673ea7e489e984543ca05fe0ff373a6f3ed4eeeaafd18292e3b182c25216aeb80a9411a57044d20b6c4004c730a78d79550dc2f22ba1c9c05e1d15e0fcadb6b1b353f028109fd193cb7c14af3251e6940572c7cd4243977896504ce0b59b17e8da04de5eb046a92f1877b55d43def3cc11a69a11050a8abdceb45bc1f09a22960fdffce720e5ed5767fbb62be1fd369dcdea861fd8582d01666a08bf3c8fb691ac5d2afca82f4759029f8425374ae4a4c91d44d05cb1a64193319d9413de7d2cfdffe253888535a8493ab8a0949a870ae512d2137630e2e4b2d772f6ee9d3b9d8cadd2f6dc34922701b21fa69f1be6d0367a26ca")
    threshold_count = 0
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

    message = b"hello Alice, this is Bob"
    # XXX choose a more interesting destination
    alice_route = route_factory.build_route(pki.identities()[0])

    # XXX create_nym method should be renamed to create_reply_block in
    # a future version of sphinxmixcrypto
    reply_block = alice_client.protocol.sphinx_client.create_nym(alice_route, pki)

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
    yield alice_received_d
