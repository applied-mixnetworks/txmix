"""
Interfaces for writing mix nets
"""

from zope.interface import Interface, Attribute


class IMixClientTransport(Interface):
    """
    Interface for a two-way mix network client transport.
    """

    name = Attribute("""name of transport handler""")

    def received(message):
        """
        This function is called when a message is received from the mix network.
        """

    def send(addr, message):
        """
        Send a message to a mix network node identified by node_id.
        """


class IEncodingHandler(Interface):

    def serialize(message):
        """
        serialize a message and return the result
        """

    def deserialize(message):
        """
        deserialize a message and return the result
        """
    
class INymClient(Interface):

    def create_nym():
        """
        Generates a nym and single use reply block after
        registering them with the nymserver.
        Returns the nym.
        """

    def reply(nym, message):
        """
        """


class INymServer(Interface):

    def received(nym, message):
        """
        """

    def add_nym(nym, surb):
        """
        Associates a nym with a single use reply block.
        """


class IPKIClient(Interface):

    def get_consensus():
        """
        Returns a consensus dict of type: node id -> node descriptor
        """

    def register(mix_descriptor):
        """
        Register a mix node with the PKI.
        """

    def getAddr(transport_handler_name, node_id):
        """
        """

class NodeDescriptor(object):

    def __init__(self, id, pub_key, transport_name, addr):
        self.id = id
        self.public_key = pub_key
        self.transport_name = transport_name
        self.addr = addr
