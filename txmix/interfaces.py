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
