
from __future__ import print_function

from sphinxmixcrypto import rand_subset, SphinxClient, create_forward_message


class Client(object):

    def __init__(self, params, pki, transport, encoding):
        self.params = params
        self.sphinx_client = SphinxClient(params)
        self.pki = pki
        self.transport = transport
        self.encoding = encoding

    def generate_route(self, destination):
        """
        given a destination node ID a randomly chosen
        route is returned: a list of mix node IDs
        where the last element is the destination
        """
        return rand_subset(self.pki.get_consensus().keys(), self.params.r-1) + [destination]

    def received(self, message):
        sphinx_message = self.encoding.deserialize(message)
        return self.sphinx_client.decrypt(sphinx_message)

    def send(self, destination, message):
        print("client send")
        route = self.generate_route(destination)
        first_hop_addr = self.pki.getAddr(self.transport.name, route[0])
        consensus = self.pki.get_consensus()
        node_map = {}
        for node_id, node_desc in consensus.items():
            node_map[node_id] = node_desc.public_key
        header, delta = create_forward_message(self.params, route, node_map, b"dest", message)
        sphinx_packet = {
            "header": header,
            "delta": delta,
        }
        serialized_message = self.encoding.serialize(sphinx_packet)
        self.transport.send(first_hop_addr, serialized_message)
