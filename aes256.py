#this is an algorithm for 256 bit AES with custom padding and initialisation vector function
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto import Random
from Crypto.Hash import SHA256
import base64
import sys
# padding used -> PKCS7

def encrypt(key, message, keytype):

    message = message.encode()

    if keytype == "hex":
        key = bytes(bytearray.fromhex(key))

    else:
        key = key.encode()
        key = SHA256.new(key).digest()

    init_vector = Random.new().read(AES.block_size)
    cipher = AES.new(key,AES.MODE_CBC, init_vector)
    data = init_vector + cipher.encrypt(pad(message,AES.block_size)) # maintaining access to IV
    return base64.b64encode(data).encode()
    # return data

def decrypt(key, message, keytype):

    message = base64.b64decode(message)

    if keytype == "hex":
        key = bytes(bytearray.fromhex(key))

    else:
        key = key.encode()
        key = SHA256.new(key).digest()

    init_vector = message[:AES.block_size] #finally the use of slicing in python
    decryptor = AES.new(key, AES.MODE_CBC, init_vector)
    data = unpad(decryptor.decrypt(message),AES.block_size)
    final = data[AES.block_size:]
    return final

if __name__ == "__main__":
    choice = sys.argv[1]
    if choice =="encrypt":
        message = sys.argv[2]
        key = sys.argv[3]
        keytype = sys.argv[4]
        print(encrypt(key,message,keytype))
    
    elif choice =="decrypt":
        cipher_text = sys.argv[2]
        key = sys.argv[3]
        keytype = sys.argv[4]
        print(decrypt(key,cipher_text,keytype))

