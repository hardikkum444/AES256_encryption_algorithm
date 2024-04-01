import os
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.Hash import SHA256
import base64



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



def encrypt_directory(key, keytype, directory_path, output_directory):
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
    
    for filename in os.listdir(directory_path):
        if filename.endswith('.txt'):  # You can change the file extension as needed
            input_file = os.path.join(directory_path, filename)
            output_file = os.path.join(output_directory, filename)
            encrypt_file(key, keytype, input_file, output_file)

def decrypt_directory(key, keytype, directory_path, output_directory):
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
    
    for filename in os.listdir(directory_path):
        if filename.endswith('.txt'):  # You can change the file extension as needed
            input_file = os.path.join(directory_path, filename)
            output_file = os.path.join(output_directory, filename)
            decrypt_file(key, keytype, input_file, output_file)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='File encryption/decryption tool')
    parser.add_argument('-e', '--encrypt', action='store_true', help='Encrypt file or directory')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Decrypt file or directory')
    parser.add_argument('-k', '--key', type=str, required=True, help='Encryption/Decryption key')
    parser.add_argument('-ky', '--keytype', type=str, required=True, choices=['string', 'hex'], help='Key type')
    parser.add_argument('-i', '--input', type=str, required=True, help='Input file or directory path')
    parser.add_argument('-o', '--output', type=str, required=True, help='Output file or directory path')

    args = parser.parse_args()

    if args.encrypt:
        if os.path.isfile(args.input):
            encrypt_file(args.key, args.keytype, args.input, args.output)
            print(f"File encrypted successfully. Encrypted file saved to {args.output}")
        elif os.path.isdir(args.input):
            encrypt_directory(args.key, args.keytype, args.input, args.output)
            print(f"All files in directory encrypted successfully. Encrypted files saved to {args.output}")
    elif args.decrypt:
        if os.path.isfile(args.input):
            decrypt_file(args.key, args.keytype, args.input, args.output)
            print(f"File decrypted successfully. Decrypted file saved to {args.output}")
        elif os.path.isdir(args.input):
            decrypt_directory(args.key, args.keytype, args.input, args.output)
            print(f"All files in directory decrypted successfully. Decrypted files saved to {args.output}")



# Encrypt a single file
# python fileEncrypt.py -e -k 1234 -ky string -i working.txt -o output.txt

# Encrypt all files in a directory
# python fileEncrypt.py -e -k 1234 -ky string -i input_directory -o output_directory

# Decrypt a single file
# python fileEncrypt.py -d -k 1234 -ky string -i output.txt -o working_decrypted.txt

# Decrypt all files in a directory
# python fileEncrypt.py -d -k 1234 -ky string -i output_directory -o input_directory_decrypted

