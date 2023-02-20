# CTF-2018---Rule86-Assignment_Stream_cipher_Cyber_security
Obtaining the Keystream

In this assignment, we have provided 4 files:-
Hint.gif.enc —> An encrypted GiF
Super_cipher.py.enc —> An encrypted Python script
Mssd.txt.enc —-> An encrypted text
Mssd.txt → txt file
solution.py  → Solution of assignment

In a synchronous stream cipher, a key stream is generated with a pseudorandom number generator, and the generated stream of bytes is xored with the message to get the ciphertext. In this scheme, the PRNG is parameterized by a secret key.
Since we know that ciphertext = keystream ^ message, and we know a ciphertext and message pair (mssd.txt and mssd.txt.enc), we can calculate part of the keystream by calculating keystream = ciphertext ^ message.
One we know part of the keystream, we can decrypt other ciphertexts by just xoring them with the keystream.
keystream = mssd.txt XOR mssd.txt.enc
## fstream = keystream

<The Key is saved in output file for future use>





Partial Decryption: 
At this point, we can only decrypt as many bytes of ciphertext as we have bytes of the keystream (aka the size of mssd.txt). Because of this, we can't fully decrypt any of the other files, as they're all too large.
As a start, we decrypted the super_cipher.py.enc file to see some of the code that was used for the cipher.
Here is the partially decrypted code:
Super_cipher.py = Super_cipher.py.enc XOR keysteam

Output ➖

Since the keystream was reused to encrypt super_cipher.py.enc (768 bytes), it can be used to partially decrypt 511 bytes of the file, saved as super_cipher.py. Examining this file yields some information on how the cipher keystream was generated.


Full Decryption
As the keystream had been reused to encrypt super_cipher.py and hint.gif, it can be used again to decrypt both files. However, the extracted keystream of 511 bytes is not enough to fully decrypt super_cipher.py.enc (768 bytes) and hint.gif.enc (24,256 bytes). Hence, there is a need to make use of next() from the partially decrypted super_cipher.py to extend the keystream.
This was done by extracting the first 32 bytes of the keystream, then using it to XOR the first 32 bytes of the encrypted file. The 32-byte keystream was then fed into the next() function to obtain the next 32 bytes of the keystream. Subsequent 32 byte blocks of the encrypted file can then be iteratively decoded by generating keystream blocks as required until the end-of-file



############################# Output Full Decryption of super_cipher.py.enc
#!/usr/bin/env python3


import argparse
import sys


parser = argparse.ArgumentParser()
parser.add_argument("key")
args = parser.parse_args()


RULE = [86 >> i & 1 for i in range(8)]
N_BYTES = 32
N = 8 * N_BYTES


def next(x):
  x = (x & 1) << N+1 | x << 1 | x >> N-1
  y = 0
  for i in range(N):
    y |= RULE[(x >> i) & 7] << i
  return y


# Bootstrap the PNRG
keystream = int.from_bytes(args.key.encode(),'little')
for i in range(N//2):
  keystream = next(keystream)


# Encrypt / decrypt stdin to stdout
plaintext = sys.stdin.buffer.read(N_BYTES)
while plaintext:
  sys.stdout.buffer.write((
    int.from_bytes(plaintext,'little') ^ keystream
  ).to_bytes(N_BYTES,'little'))
  keystream = next(keystream)
  plaintext = sys.stdin.buffer.read(N_BYTES)

############################# Output Full Decryption of hint.gif
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





From next() to prev()
Since the seed was fed through the next() function 128 times to initialize the keystream, the function has to be reversed so that the keystream can be stepped backwards until we reobtain the seed. The next() function was further examined



(x & 1) << N+1 takes the least significant bit (x & 1) and left shifts it by 257 bits (<< N+1). This results in a value of 258 bits with the value of the least significant bit at the "head" (most significant bit) followed by 0s.

x << 1 left shift the original input by 1 bit, resulting in a value of 257 bits with 0 at the "tail" (least significant bit).

x >> N-1 right shifts the original input by 255 bits, resulting in a value of 1 bit containing the original most significant bit.

OR (|) is performed on all three bit values, combining them to a 258-bit long value. The 
overall effect of the line of code can be represented as:




For example, if y = 0b1011, reading from left to right

Merging the bit triplets, we get the following possible values of x:

We only accept bitstreams with matching front and back 2 bits (yxABCDEFyx) due to the bitshifting operation carried out on x in next().
We recover the previous bitstream after trimming the head and tail bits on valid values of x
(yxABCDEFyx → xABCDEFy)

The function to reverse next() is written into prev()

Extracting the Seed
To extract the seed from the keystream, the initial 32-byte keystream block is fed into the prev() function and iterated 128 (N//2) times, the same number of times the seed was iterated to get the initial keystream block. The final int value is then converted to bytes before being decoded into a utf-8 string:

