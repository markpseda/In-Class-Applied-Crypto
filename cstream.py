import os
from Crypto.Util.number import *
import hashlib



# CONVERSIONS 
# These are the 12 1-line transformations that are most useful to crypto CTF problems

#THIS IS THE PYTHON 2 VERSION
#in every CTF or crypto session this line is my first include
from Crypto.Util.number import *

#Our four formats are plaintext (ASCII), hex digest, integer, and byte array
pt="this is plaintext"

#1) ASCII to HEX
hexdigest = pt.encode('hex')
#2) HEX to ASCII
hexdigest.decode('hex')

#3) ASCII to Integer
int_pt = bytes_to_long(pt)
#4) Integer to ASCII
long_to_bytes(int_pt)

#5) Integer to hex
format(int_pt, 'x')
#6) hex to Integer
int(hexdigest, 16)

#7) ASCII to byte array
pt_as_bytes = map(ord, pt)
#8) byte array to ASCII
"".join(map(chr, pt_as_bytes))

#9) byte array to hex
"".join(map(lambda x: hex(x)[2:], pt_as_bytes))

#10) hex to byte array
[int(hexdigest[i:i+2], 16) for i in range(0, len(hexdigest), 2)]

#11) byte array to int
bytes_to_long("".join(map(chr, pt_as_bytes)))

#12) int to byte array
map(ord, long_to_bytes(int_pt))

# END Conversions



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



# HELPER STUFF
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


message = '4c701b07d5839267e97ac4e1c4afd312ff658c882f7ca806c6c48efef14cb87cb247'

nonce = message[:12]


actual_message = message[12:]

print("Nonce plain: " + nonce)

nonce_hex = nonce.decode('hex')
print("Nonce hex: " + nonce_hex)

nonce_array = map(ord, nonce)
nonce_concat_array = "".join(map(chr, nonce_array))

print("Nonce concat: " + nonce_concat_array)

print("Nonce: " + nonce_hex)
print("Message: " + message)

# should be 343167251
seed = generate_seed('salmon', nonce_hex)

print(seed)

mygen = crand(seed)

def encode_decode(input_text, num_bytes_nonce, password):

    nonce = input_text[:(num_bytes_nonce * 2)].decode('hex')
    

    seed = generate_seed(password, nonce)

    print(seed)

    input_text_actual = input_text[(num_bytes_nonce*2):]

    print(input_text_actual)
    gen = crand(seed)

    stream = [gen.next() for i in range(len(input_text_actual) / 2)]
    for i in range(len(stream)):
        stream[i] = stream[i] % 256

    print(stream)

    messageVals = map(ord, input_text_actual.decode('hex'))

    print(messageVals)

    output = []
    for i in range(len(stream)):
        output.append(stream[i] ^ messageVals[i])

    final = ""
    for i in range(len(output)):
        final += chr(output[i])

    return final


stream = [mygen.next() for i in range(len(actual_message) / 2)]
for i in range(len(stream)):
    stream[i] = stream[i] % 256

print stream

messageVals = map(ord, actual_message.decode('hex'))

print messageVals

output = []
for i in range(len(stream)):
    output.append(stream[i] ^ messageVals[i])

print output

final = ""
for i in range(len(output)):
    final += chr(output[i])

print final



print(encode_decode('4c701b07d5839267e97ac4e1c4afd312ff658c882f7ca806c6c48efef14cb87cb247', 6, 'salmon'))
