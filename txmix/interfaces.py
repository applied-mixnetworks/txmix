"""
Interfaces for writing mix nets
"""

from zope.interface import Interface, Attribute


class IMixTransport(Interface):
    """
    Interface for a two-way mix network client transport.
    """

    name = Attribute("""name of transport handler""")

    def start(addr, protocol):
        """
        start the transport
        """

    def received(message):
        """
        This function is called when a message is received from the mix network.
        """

    def send(addr, message):
        """
        Send a message to a mix network node identified by addr.
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

    def get_mix_addr(transport_handler_name, node_id):
        """
        returns the adress of the mix specified by node_id
        """

    def get_nymserver_addr(transport_handler_name):
        """
        returns the address of the nymserver
        """
