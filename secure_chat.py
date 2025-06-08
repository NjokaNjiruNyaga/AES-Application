from cryptography.fernet import Fernet

# Generate and return a new key
def generate_key():
    return Fernet.generate_key()

# Encrypt the message
def encrypt_message(key, message):
    cipher = Fernet(key)
    encrypted = cipher.encrypt(message.encode())
    return encrypted

# Decrypt the message
def decrypt_message(key, encrypted_message):
    cipher = Fernet(key)
    decrypted = cipher.decrypt(encrypted_message)
    return decrypted.decode()

# Run app
if __name__ == "__main__":
    print("=== Secure AES Chat App ===")
    choice = input("Choose: 1 = Send (encrypt), 2 = Receive (decrypt): ")

    if choice == "1":
        message = input("Enter your message: ")
        key = generate_key()
        encrypted = encrypt_message(key, message)
        print("\n--- ENCRYPTED MESSAGE ---")
        print(encrypted.decode())
        print("\n--- OTP (KEY to share securely) ---")
        print(key.decode())

    elif choice == "2":
        encrypted = input("Paste the encrypted message: ").encode()
        key = input("Enter the OTP key: ").encode()
        try:
            decrypted = decrypt_message(key, encrypted)
            print("\n--- DECRYPTED MESSAGE ---")
            print(decrypted)
        except:
            print("Decryption failed. Make sure the key and message are correct.")
