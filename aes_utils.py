from Crypto.Cipher import AES
import base64
import os

# --- Padding and unpadding functions ---
def pad(s):
    padding = 16 - len(s) % 16
    return s + chr(padding) * padding

def unpad(s):
    padding = ord(s[-1])
    return s[:-padding]

# --- Generate a 128-bit AES key (16 bytes) ---
def generate_key():
    return os.urandom(16)  # Secure random key

# --- Encrypt the message with the AES key ---
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(message)
    encrypted_bytes = cipher.encrypt(padded.encode())
    # Convert to base64 so it's easy to copy and send
    return base64.b64encode(encrypted_bytes).decode()

# --- Decrypt the message using the AES key ---
def decrypt_message(key, encrypted_base64):
    encrypted_bytes = base64.b64decode(encrypted_base64)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_bytes).decode()
    return unpad(decrypted)
