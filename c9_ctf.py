
from Crypto.Util.number import *
import hashlib

import os

def XOR(message, key):
    return ''.join(chr(ord(c)^ord(k)) for c,k in izip(message, cycle(key)))

dummy = "teststringninjafish"

dummy_flip = dummy[::-1]


message = "291c1a1654081652063145303b0d53192d1b0b333d227e7f26273d5b07060f0e4e4900494e0e0f06075b3d27267f7e223d330b1b2d19530d3b3045310652160854161a1c29"

thing = XOR(message[:(len(message) / 2)], message[(len(message) / 2):])

print(thing)