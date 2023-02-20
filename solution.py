import sys
# Read two files as byte arrays
text = bytearray(open("mssd.txt", 'rb').read())
enc = bytearray(open("mssd.txt.enc", 'rb').read())

# Set the length to be the smaller one
size = len(text) if len(text) < len(enc) else len(enc)
xord_byte_array = bytearray(size)

# XOR between the files
for i in range(size):
	xord_byte_array[i] = text[i] ^ enc[i]

# Write the XORd bytes to the output file	
open("output", 'wb').write(xord_byte_array)
f_stream = bytearray(open("output", 'rb').read())
print(f_stream)

########################################################################### partial Decryption of python file ######################
f4= bytearray(open("super_cipher.py.enc", 'rb').read())
# Set the length to be the smaller one
size11 = len(f_stream) if len(f_stream) < len(f4) else len(f4)
xord_byte_array11 = bytearray(size11)
# XOR between the files
for i in range(size11):
	xord_byte_array11[i] = f_stream[i] ^ f4[i]
open("super_cipher.py", 'wb').write(xord_byte_array11)

#######################Full Decryption########################################################################
f_stream = bytearray(open("output", 'rb').read())
key=f_stream[:32]

RULE = [86 >> i & 1 for i in range(8)]
N_BYTES = 32
N = 8 * N_BYTES

def next(x):
  x = (x & 1) << N+1 | x << 1 | x >> N-1
  y = 0
  for i in range(N):
    y |= RULE[(x >> i) & 7] << i
  return y

keystream = int.from_bytes(key,'little')

for i in range(900):
  keystream = next(keystream)
  key+=keystream.to_bytes(32,'little')

print(key)
open("final_big_key", 'wb').write(key)

big_key = bytearray(open("final_big_key", 'rb').read())
f4= bytearray(open("super_cipher.py.enc", 'rb').read())
# Set the length to be the smaller one
size11 = len(big_key) if len(big_key) < len(f4) else len(f4)
xord_byte_array11 = bytearray(size11)
# XOR between the files
for i in range(size11):
	xord_byte_array11[i] = big_key[i] ^ f4[i]
	
open("big_complete.py", 'wb').write(xord_byte_array11)
print(xord_byte_array11.decode())

########################## Decryption Of Hint Image##########################################################
big_key = bytearray(open("final_big_key", 'rb').read())
Hint_img=f4= bytearray(open("hint.gif.enc", 'rb').read())
# Set the length to be the smaller one

size_img = len(big_key) if len(big_key) < len(Hint_img) else len(Hint_img)
xord_byte_array112 = bytearray(size_img)
# XOR between the files
for i in range(size_img):
	xord_byte_array112[i] = big_key[i] ^ Hint_img[i]
open("decryptHint.gif", 'wb').write(xord_byte_array112)

############################################ """Recovers seed used to generate keystream #################

def previous(y):
 # initial bit to triplet mapping
    bit_to_triplet = {
        '0': ['000', '011', '101', '111'],
        '1': ['001', '010', '100', '110'],
        }
    # subsequent triplet and bit mapping
    triplet_to_triplet = {
        '000': {
            '0': '0',
            '1': '1',
            },
        '011': {
            '0': '1',
            '1': '0',
            },
        '101': {
            '0': '1',
            '1': '0',
            },
        '111': {
            '0': '1',
            '1': '0',
            },
        '001': {
            '0': '1',
            '1': '0',
            },
        '010': {
            '0': '1',
            '1': '0',
            },
        '100': {
            '0': '0',
            '1': '1',
            },
        '110': {
            '0': '1',
            '1': '0',
            },
        }    
    y = list(format(y, f'0{N}b'))
    # 4 possible inital bitstreams
    bitstreams = bit_to_triplet[y.pop(0)].copy()
    while y:
        bit = y.pop(0)
        # extend each bitstream according to value of bit
        for i, stream in enumerate(bitstreams):
            # check last 3 bits of stream for triplet block
            bitstreams[i] += triplet_to_triplet[stream[-3:]][bit]
    # find valid bitstream with matching 2 bits from head and tail (yxABCDEFyx)
    for stream in bitstreams:
        if stream[:2] == stream[-2:]:
            # trim bits from head and tail (yxABCDEFyx --> xABCDEFy)
            x = int(stream[1:-1], 2)
            return x

f_stream = bytearray(open("output", 'rb').read())
seed = int.from_bytes(f_stream[:N_BYTES], 'little')
    # do 128 (N//2) iterations of prev() to reverse next()
for i in range(N//2):
 seed = previous(seed)
seed = seed.to_bytes(N_BYTES, 'little').decode()
print(seed)
