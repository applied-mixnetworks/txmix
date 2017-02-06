
from __future__ import print_function

from sphinxmixcrypto import SphinxParams


DEFAULT_CRYPTO_PARAMETERS = SphinxParams(5, 1024)


class NodeDescriptor(object):

    def __init__(self, id, pub_key, transport_name, addr):
        self.id = id
        self.public_key = pub_key
        self.transport_name = transport_name
        self.addr = addr
