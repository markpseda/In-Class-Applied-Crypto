from Crypto.Util.number import *
from Crypto.Cipher import AES
import hashlib, pwn, hmac, binascii

"""
secret = "markrulz"


secret_plus = "markrulzbanana"

hash1 = hashlib.sha256(secret_plus).hexdigest()

print(hash1)


NewPayload_hashpump = 'banana\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00plemongrass'

new_hexdigest_hashpump = '29c737444116789fde5aafd690d71cc37851c7c4163be9bc8eaa95041f2d3371'

hash2 = hashlib.sha256(secret + NewPayload_hashpump).hexdigest()

print(hash2)
"""

print(hmac.new("secretkey", "forge this punks", hashlib.sha256).hexdigest())

k = "secretkey"
msg = "forge this punks"

kplus = k + "\x00"*(64-len(k))
ipad = "\x36"*64
opad = "\x5C"*64

def XOR(raw1, raw2):
  return binascii.unhexlify(format(int(binascii.hexlify(raw1), 16) ^ int(binascii.hexlify(raw2), 16), 'x'))

tag = hashlib.sha256(XOR(kplus, opad) + hashlib.sha256(XOR(kplus, ipad) + msg).digest()).digest()

print binascii.hexlify(tag)
iv = chr(0)*16
cipher = AES.new("andy love simone", AES.MODE_CBC, iv)

pt = "andy love simoneandy love simone"

ct1 = cipher.encrypt(iv)
ct2 = cipher.encrypt(XOR(ct1, pt[:16]))
ct3 = cipher.encrypt(XOR(ct2, pt[16:32]))
ct4 = cipher.encrypt(XOR(ct3, pt[32:]))

print(ct4.encode('hex'))