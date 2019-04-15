from itertools import cycle, izip

from Crypto.Util.number import *
import hashlib

import os

def XOR(message, key):
    return ''.join(chr(ord(c)^ord(k)) for c,k in izip(message, cycle(key)))


#PYTHON 2...

def generate_seed(secret, nonce):
    return bytes_to_long(hashlib.sha256(nonce + secret).digest()) % 2**32

def crand(seed):
    r=[]
    r.append(seed)
    for i in range(30):
        r.append((16807*r[-1]) % 2147483647)
        if r[-1] < 0:
            r[-1] += 2147483647
    for i in range(31, 34):
        r.append(r[len(r)-31])
    for i in range(34, 344):
        r.append((r[len(r)-31] + r[len(r)-3]) % 2**32)
    while True:
        next = r[len(r)-31]+r[len(r)-3] % 2**32
        r.append(next)
        yield (next >> 1 if next < 2**32 else (next % 2**32) >> 1)

def generate_byte_array(seed, num_bytes):
  generator = crand(seed)
  return [generator.next() % 256 for _ in range(num_bytes)] 

def encrypt(plaintext, secret):
  nonce = os.urandom(6)
  thisseed = generate_seed(secret, nonce)
  thiskey = generate_byte_array(thisseed, len(plaintext))
  ct = nonce
  for i in range(len(plaintext)):
    ct += chr(ord(plaintext[i]) ^ thiskey[i])
  return ct

def decrypt(ciphertext, secret):
  nonce = ciphertext[:6]
  encrypted_message = ciphertext[6:]
  thisseed = generate_seed(secret, nonce)
  thiskey = generate_byte_array(thisseed, len(encrypted_message))
  pt = ''
  for i in range(len(encrypted_message)):
    pt += chr(ord(encrypted_message[i]) ^ thiskey[i])
  return pt

message = "Hllo dis is my message"

encrypted = encrypt(message, "secret")
print(encrypted)
decrypted = decrypt(encrypted, "secret")
print(decrypted)

andys = "d32c86be69f2a5ffcc7bcc87a581ba56cc58fca70c228c34ef9db9310edbc7df934870f1b1714319"
andys = andys.decode('hex')

andys_decrypted = decrypt(andys, "banana salmon")

print(andys_decrypted)

message1 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c'

encrypted1 = '546e140f717ffd1bad647e56db260730f5a503b38d5ba10c93d5f064c6263ac439b9d339e05abd0c3697df80559c59b9e1e2afcafffd7af631d0b3'
encrypted2 = '546e140f717fa343f13d2b189f744a7afda907888962a80b94dcfe57ce3025db3baed312fa42af2b3b82c1a978b76b91f9da8ae1dddf43dd06f49fbe514cc21aa360ebde4da8f48aa771be9563edbe2574769bd5d0febe0a59117a3437e6eb3e8b1a9f22d1b0007e1aaf'

message1_hex = message.encode('hex')

encrypted1_hex = encrypted1.decode('hex')
encrypted2_hex = encrypted2.decode('hex')

xord = XOR(message1_hex, encrypted1[6:])

#print(xord)

decryptz = XOR(encrypted2[6:], xord)
print(decryptz)