#!/usr/bin/env python

import click
from twisted.internet import reactor
from sphinxmixcrypto import PacketReplayCacheDict, SphinxParams

from txmix import OnionTransportFactory
from txmix import ThresholdMixNode
from txmix import RandReader, generate_node_keypair, generate_node_id, DummyPKI, SphinxNodeKeyState


@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--tor-control-unix-socket', default="", type=str, help="unix socket name for connecting to the tor control port")
@click.option('--tor-control-tcp-host', default="", type=str, help="tcp host for connecting to the tor control port")
@click.option('--tor-control-tcp-port', default=0, type=int, help="tcp port for connecting to the tor control port")
@click.option('--onion-unix-socket', default="", type=str, help="unix socket file that our onion service should use")
@click.option('--onion-tcp-interface-ip', default="", type=str, help="the interface to listen on for onion connections")
@click.option('--tor-data', default="", type=str, help="launch tor data directory")
def main(tor_control_unix_socket,
         tor_control_tcp_host,
         tor_control_tcp_port,
         onion_unix_socket,
         onion_tcp_interface_ip,
         tor_data):
    rand_reader = RandReader()
    public_key, private_key = generate_node_keypair(rand_reader)
    node_id = generate_node_id(rand_reader)
    replay_cache = PacketReplayCacheDict()
    key_state = SphinxNodeKeyState(public_key, private_key)
    params = SphinxParams(5, 1024)  # 5 hops max and payload 1024 bytes
    pki = DummyPKI()
    threshold_count = 100
    transport_factory = OnionTransportFactory(reactor,
                                              params,
                                              tor_control_unix_socket.encode('utf-8'),
                                              tor_control_tcp_host.encode('utf-8'),
                                              tor_control_tcp_port,
                                              onion_unix_socket.encode('utf-8'),
                                              onion_tcp_interface_ip.encode('utf-8'))
    d = transport_factory.build_transport()

    def got_transport(transport):
        mix = ThresholdMixNode(threshold_count, node_id, replay_cache, key_state, params, pki, transport)
        return mix.start()

    d.addCallback(got_transport)
    reactor.run()


if __name__ == '__main__':
    main()
