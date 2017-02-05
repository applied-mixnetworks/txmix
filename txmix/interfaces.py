"""
Interfaces for writing mix nets
"""

from zope.interface import Interface, Attribute


class IMixTransport(Interface):
    """
    Interface for a two-way mix network client transport.
    """

    name = Attribute("""name of transport handler""")

    def register_protocol(protocol):
        """
        register the protocol
        """

    def start():
        """
        start the transport
        """

    def send(addr, message):
        """
        Send a message to a mix network node identified by addr.
        """
