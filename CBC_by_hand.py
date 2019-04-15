from Crypto.Cipher import AES, XOR
from itertools import cycle, izip

def XOR(message, key):
    return ''.join(chr(ord(c)^ord(k)) for c,k in izip(message, cycle(key)))


key = "andy love simone"

hexDigest = '000102030405060708090a0b0c0d0e0f'

hexDigest = hexDigest.decode('hex')


message = "abcdefghijklmnopqrstuvwxyzabcdef"

cipher = AES.new(key)

pt1 = message[:16]
pt2 = message[16:]

print(hexDigest)
print(len(hexDigest))

print(pt1)

thing = XOR(pt1, hexDigest)

print(thing)

opt1 = cipher.encrypt(thing)

print(opt1.decode('hex'))