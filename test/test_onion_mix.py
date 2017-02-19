# -*- coding: utf-8 -*-

import pytest
import binascii
import attr
import types
import json
import os
import sys
import txtorcon

from eliot import add_destination
from twisted.internet import reactor, defer, endpoints
from twisted.internet.protocol import Protocol

from sphinxmixcrypto import SphinxParams, PacketReplayCacheDict

from txmix import OnionTransportFactory, ThresholdMixNode, IMixTransport, ContinuousTimeMixNode
from txmix.client import MixClient, RandomRouteFactory, CascadeRouteFactory
from txmix.onion_transport import OnionDatagramProxyFactory
from test_txmix import generate_node_id, generate_node_keypair, ChachaNoiseReader, SphinxNodeKeyState, DummyPKI


# tell eliot to log a line of json for each message to stdout
def stdout(message):
    sys.stdout.write(json.dumps(message) + "\n")


add_destination(stdout)


@pytest.inlineCallbacks
def test_onion_datagram_proxy():
    received_buffer = []
    received_d = defer.Deferred()

    def received(data):
        received_buffer.append(data)
        received_d.callback(None)

    received_size = 10
    proxy_factory = OnionDatagramProxyFactory(received_size, received)
    protocol = proxy_factory.buildProtocol(123)
    packet = b"A" * received_size
    protocol.dataReceived(packet)
    assert received_buffer[0] == packet

    service_port = yield txtorcon.util.available_tcp_port(reactor)
    service_endpoint_desc = "tcp:interface=127.0.0.1:%s" % service_port
    service_endpoint = endpoints.serverFromString(reactor, service_endpoint_desc)
    yield service_endpoint.listen(proxy_factory)

    client_endpoint_desc = "tcp:127.0.0.1:%s" % service_port
    client_endpoint = endpoints.clientFromString(reactor, client_endpoint_desc)
    client_protocol = Protocol()
    yield endpoints.connectProtocol(client_endpoint, client_protocol)
    client_protocol.transport.write(packet)
    client_protocol.transport.loseConnection()
    yield received_d
    assert received_buffer[0] == packet


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


@attr.s()
class FakeMixProtocol(object, Protocol):
    """
    this protocol is useful for testing transports
    """
    packet_received_handler = attr.ib(validator=attr.validators.instance_of(types.FunctionType))

    def make_connection(self, transport):
        assert IMixTransport.providedBy(transport)
        transport.register_protocol(self)
        d = transport.start()
        self.transport = transport
        return d

    def received(self, raw_packet):
        self.packet_received_handler(raw_packet)


@pytest.inlineCallbacks
def test_onion_transport():
    """
    integration test for onion transport
    """
    chutney_control_port = os.environ.get('CHUTNEY_CONTROL_PORT')
    if chutney_control_port is None:
        print "CHUTNEY_CONTROL_PORT not set, aborting test"
        return

    params = SphinxParams(max_hops=5, payload_size=1024)
    sphinx_packet_size = params.get_sphinx_forward_size()
    transport_factory = create_transport_factory(sphinx_packet_size, chutney_control_port)
    transport = yield transport_factory.build_transport()
    received_d = defer.Deferred()
    received_buffer = []

    def packet_received(packet):
        print "packet received of len %s" % len(packet)
        received_buffer.append(packet)
        received_d.callback(None)

    protocol = FakeMixProtocol(packet_received)
    yield protocol.make_connection(transport)
    onion_host, onion_port = transport.addr
    tor_endpoint = transport.tor.stream_via(onion_host, onion_port)
    send_message_protocol = Protocol()
    remote_mix_protocol = yield endpoints.connectProtocol(tor_endpoint, send_message_protocol)
    message = b"A" * sphinx_packet_size
    remote_mix_protocol.transport.write(message)
    remote_mix_protocol.transport.loseConnection()
    yield received_d
    assert received_buffer[0] == message


@pytest.inlineCallbacks
def test_onion_threshold_cascade_mix():
    """
    integration test for threshold mix using onion transport
    """
    chutney_control_port = os.environ.get('CHUTNEY_CONTROL_PORT')
    if chutney_control_port is None:
        print "CHUTNEY_CONTROL_PORT not set, aborting test"
        return

    params = SphinxParams(max_hops=5, payload_size=1024)
    sphinx_packet_size = params.get_sphinx_forward_size()
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

    random_route_factory = RandomRouteFactory(params, pki, rand_reader)
    cascade_route = random_route_factory.build_route()
    route_factory = CascadeRouteFactory(cascade_route)

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

    for message_num in range(threshold_count + 2):
        reply_block = alice_client.create_reply_block()
        message = b"hello Alice, this is Bob. message %s" % message_num
        yield alice_client.reply(reply_block, message)

    for message_num in range(threshold_count):
        yield alice_received_d
        alice_received_d = defer.Deferred()


@pytest.inlineCallbacks
def test_onion_continuous_time_mix():
    """
    integration test for continuous time mix
    """
    chutney_control_port = os.environ.get('CHUTNEY_CONTROL_PORT')
    if chutney_control_port is None:
        print "CHUTNEY_CONTROL_PORT not set, aborting test"
        return

    params = SphinxParams(max_hops=3, payload_size=1024)
    sphinx_packet_size = params.get_sphinx_forward_size()
    transport_factory = create_transport_factory(sphinx_packet_size, chutney_control_port)
    pki = DummyPKI()
    rand_reader = ChachaNoiseReader("4704aff4bc2aaaa3fd187d52913a203aba4e19f6e7b491bda8c8e67daa8daa67")
    max_delay = 60
    mixes = []
    for mix_num in range(3):
        node_id = generate_node_id(rand_reader)
        replay_cache = PacketReplayCacheDict()
        public_key, private_key = generate_node_keypair(rand_reader)
        key_state = SphinxNodeKeyState(public_key, private_key)
        transport = yield transport_factory.build_transport()
        mix = ContinuousTimeMixNode(node_id, max_delay, transport, replay_cache, key_state, params, pki, reactor)
        yield mix.start()
        mixes.append(mix)

    route_factory = RandomRouteFactory(params, pki, rand_reader)
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

    for message_num in range(3):
        reply_block = alice_client.create_reply_block()
        message = b"hello Alice, this is Bob. message %s" % message_num
        yield alice_client.reply(reply_block, message)

    for message_num in range(3):
        yield alice_received_d
        alice_received_d = defer.Deferred()
