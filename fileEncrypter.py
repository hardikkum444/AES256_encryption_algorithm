import os
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.Hash import SHA256
import base64

# My AES encryption and decryption function

def encrypt(key, message, keytype):
    message = message.encode()

    if keytype == "hex":
        key = bytes(bytearray.fromhex(key))
    else:
        key = key.encode()
        key = SHA256.new(key).digest()

    init_vector = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, init_vector)
    data = init_vector + cipher.encrypt(pad(message, AES.block_size))
    return base64.b64encode(data).decode()

def decrypt(key, message, keytype):
    message = base64.b64decode(message)

    if keytype == "hex":
        key = bytes(bytearray.fromhex(key))
    else:
        key = key.encode()
        key = SHA256.new(key).digest()

    init_vector = message[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, init_vector)
    data = unpad(decryptor.decrypt(message), AES.block_size)
    final = data[AES.block_size:]
    return final.decode()

# These are the file encryption and decryption functions

def encrypt_file(key, keytype, input_file, output_file):
    with open(input_file, 'rb') as file:
        message = file.read()
    encrypted_data = encrypt(key, message.decode(), keytype)
    with open(output_file, 'w') as file:
        file.write(encrypted_data)

def decrypt_file(key, keytype, input_file, output_file):
    with open(input_file, 'r') as file:
        message = file.read()
    decrypted_data = decrypt(key, message, keytype)
    with open(output_file, 'wb') as file:
        file.write(decrypted_data.encode())

# making the parsers

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='File encryption/decryption tool')
    parser.add_argument('-e', '--encrypt', action='store_true', help='Encrypt file')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Decrypt file')
    parser.add_argument('-k', '--key', type=str, required=True, help='Encryption/Decryption key')
    parser.add_argument('-ky', '--keytype', type=str, required=True, choices=['string', 'hex'], help='Key type')
    parser.add_argument('-i', '--input', type=str, required=True, help='Input file path')
    parser.add_argument('-o', '--output', type=str, required=True, help='Output file path')

    args = parser.parse_args()

    if args.encrypt:
        encrypt_file(args.key, args.keytype, args.input, args.output)
        print(f"File encrypted successfully. Encrypted file saved to {args.output}")
    elif args.decrypt:
        decrypt_file(args.key, args.keytype, args.input, args.output)
        print(f"File decrypted successfully. Decrypted file saved to {args.output}")


# sample use case 
# py fileEncrypt.py -e -k 1234 -ky string -i working.txt -o output.txt
