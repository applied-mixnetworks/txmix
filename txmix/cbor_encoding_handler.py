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
