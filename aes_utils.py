from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib
from Crypto.Util.Padding import pad, unpad

def generate_key():
    return get_random_bytes(32)  # 256-bit key

def encrypt_message(key, plaintext):
    iv = get_random_bytes(16)  # AES block size
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_message(key, encrypted_b64):
    raw_data = base64.b64decode(encrypted_b64)
    iv = raw_data[:16]
    ciphertext = raw_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext.decode()
