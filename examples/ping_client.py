
from twisted.internet import reactor

from sphinxmixcrypto import SphinxParams
from txmix import UDPTransport
from txmix import SprayMixClient, RandomRouteFactory
from txmix import DummyPKI, RandReader


def main():
    params = SphinxParams(5, 1024)
    pki = DummyPKI()
    client_id = b"client"
    rand_reader = RandReader()
    transport = UDPTransport(reactor, ("127.0.0.1", 6779))
    route_factory = RandomRouteFactory(params, pki, rand_reader)

    def message_receive_handler(message):
        print "client received message: %s" % message

    client = SprayMixClient(params, pki, client_id, rand_reader, transport, message_receive_handler, route_factory)
    client.start()

    message = b"ping"
    route = client.generate_route()
    client.send(route, message)

    reactor.run()


if __name__ == '__main__':
    main()
