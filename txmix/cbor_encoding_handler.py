# -*- coding: utf-8 -*-

from zope.interface import implementer
from txmix.interfaces import IEncodingHandler

import cbor

@implementer(IEncodingHandler)
class CBOREncodingHandler():

    def serialize(self, message):
        return cbor.dumps(message)

    def deserialize(self, message):
        return cbor.loads(message)

    def serialize_sphinx_packet(self, alpha=None, beta=None, gamma=None, delta=None):
        sphinx_packet = {
            "alpha": alpha,
            "beta" : beta,
            "gamma": gamma,
            "delta": delta,
        }
        return self.serialize(sphinx_packet)

    def deserialize_sphinx_packet(self, message):
        sphinx_packet = self.deserialize(message)
        for key in ["alpha", "beta", "gamma", "delta"]:
            assert key in sphinx_packet
        return sphinx_packet
