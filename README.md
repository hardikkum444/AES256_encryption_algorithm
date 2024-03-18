# AES (Advanced Encryption Standard) Cipher and CBC (Cipher Block Chaining)

AES is a symmetric cipher used for encryption and decryption of data. It operates on a 4x4 grid of 128 bits (16-byte blocks) and supports key lengths of 128, 192, or 256 bits.

## AES Encryption Steps:

plaintext<br>
|<br>
|<br>
+
(XOR)@ <-- Initialisation vector (IV)<br>
|<br>
|<br>
+
block cipher <-- Key<br>
|<br>
|<br>
+
cipher text<br>

<br>

1. **Initial XOR with Key**: Plaintext is combined with the initial round key.
2. **Substitute Bytes**: Byte substitution using an AES lookup table.
3. **Shift Rows**: Rows of the grid are shifted cyclically to the left.
4. **Mix Columns**: Matrix multiplication in a Galois finite field (except in the last round).
5. **Add Round Key**: Round key is XORed with the result of the previous steps.

## AES Decryption Steps:

cipher text<br>
|<br>
|<br>
+
(XOR)@ <-- Initialisation vector (IV)<br>
|<br>
|<br>
+
block cipher <-- Key<br>
|<br>
|<br>
+
plaintext<br>



Decryption involves reversing the encryption steps, with the IV used to maintain randomness and uniqueness of ciphertexts.

### Key Points:
- AES encryption involves multiple rounds, each performing a specific transformation on the data.
- CBC mode enhances security by XORing each plaintext block with the previous ciphertext block before encryption.
- The IV is crucial for CBC mode to ensure unique ciphertexts.

## Code Example:

```python
#ENCRYPTOR WHICH WRITES THE ENCRYPTION AND THE VI TO A FILE
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

key = b'mysecretpassword' #16 bit key

cipher = AES.new(key,AES.MODE_CBC)

plaintext = b'this is some important data'

ciphertext = cipher.encrypt(pad(plaintext,AES.block_size))


with open('k_file','wb')as key_file:
    key_file.write(cipher.iv)
    key_file.write(ciphertext)

#DECRYPTOR WHICH TAKES FROM THAT FILE TO CONVERT BACK TO PLAIN TEXT
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os
import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto import Random
from Crypto.Hash import SHA256
import base64
import sys

key = b'mysecretpassword' #16 bit key

with open('k_file', 'rb') as key_file:
    iv = key_file.read(16)
    ciphertext = key_file.read()


cipher= AES.new(key,AES.MODE_CBC, iv)

plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

print(plaintext.decode())
