
from twisted.internet import reactor

from sphinxmixcrypto import SphinxParams
from txmix.transports import UDPTransport
from txmix.client import SprayMixClient
from txmix.utils import DummyPKI, RandReader


def main():
    params = SphinxParams(5, 1024)
    pki = DummyPKI()
    client_id = b"client"
    rand_reader = RandReader()
    transport = UDPTransport(reactor, ("127.0.0.1", 6779))
    client = SprayMixClient(params, pki, client_id, rand_reader, transport)
    client.start()
    reactor.run()


if __name__ == '__main__':
    main()
