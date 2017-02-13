

import attr
import click
from twisted.internet import reactor

from sphinxmixcrypto import SphinxParams, IMixPKI, IReader
from txmix import OnionTransportFactory
from txmix import MixClient, RandomRouteFactory, IMixTransport, IRouteFactory
from txmix import DummyPKI, RandReader


@attr.s
class PingClient(object):

    params = attr.ib(validator=attr.validators.instance_of(SphinxParams))
    pki = attr.ib(validator=attr.validators.provides(IMixPKI))
    client_id = attr.ib(validator=attr.validators.instance_of(bytes))
    rand_reader = attr.ib(validator=attr.validators.provides(IReader))
    transport = attr.ib(validator=attr.validators.provides(IMixTransport))
    route_factory = attr.ib(validator=attr.validators.provides(IRouteFactory))

    reply = ""
    reply_d = None

    def message_received(self, message):
        print "DEBUG: PingClient: message_received: %s" % message
        self.reply = message
        self.reply_d.callback(message)

    def start(self):
        self.client = MixClient(self.params,
                                self.pki,
                                self.client_id,
                                self.rand_reader,
                                self.transport,
                                self.message_received,
                                self.route_factory)
        d = self.client.start()
        return d

    def wait_for_reply(self):
        return self.reply_d

    def send(self, destination, message):
        """
        proxy to the MixClient's send method.
        returns a deferred
        """
        return self.client.send(destination, message)


@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--tor-control-unix-socket', default=None, type=str, help="unix socket name for connecting to the tor control port")
@click.option('--tor-control-tcp-host', default=None, type=str, help="tcp host for connecting to the tor control port")
@click.option('--tor-control-tcp-port', default=None, type=str, help="tcp port for connecting to the tor control port")
@click.option('--onion-unix-socket', default=None, type=str, help="unix socket file that our onion service should use")
@click.option('--onion-tcp-interface-ip', default=None, type=str, help="the interface to listen on for onion connections")
@click.option('--tor-data', default=None, type=str, help="launch tor data directory")
def main(tor_control_unix_socket, tor_control_tcp_host, tor_data):
    """
    send a "ping" packet and wait for a reply
    """

    params = SphinxParams(max_hops=5, payload_size=1024)
    pki = DummyPKI()
    client_id = b"client"
    rand_reader = RandReader()

    transport_factory = OnionTransportFactory(reactor, params, tor_control_unix_socket)
    route_factory = RandomRouteFactory(params, pki, rand_reader)
    destination = pki.identities()[0]  # XXX todo: pick a more interesting destination
    message = b"ping"

    d = transport_factory.buildTransport()
    client = None

    def got_transport(transport):
        client = PingClient(params, pki, client_id, rand_reader, transport, route_factory)
        return client.start()

    d.addCallback(got_transport)
    d.addCallback(lambda ign: client.send(destination, message))
    d.addCallback(lambda ign: client.wait_for_reply())

    reactor.run()


if __name__ == '__main__':
    main()
