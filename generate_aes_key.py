# generate_aes_key.py
from Crypto.Random import get_random_bytes

def generate_aes_key():
    aes_key = get_random_bytes(16)
    with open('aes_key.bin', 'wb') as key_file:
        key_file.write(aes_key)

if __name__ == "__main__":
    generate_aes_key()
    print("AES key generated and stored in aes_key.bin")
