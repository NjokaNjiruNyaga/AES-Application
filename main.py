import tkinter as tk
from tkinter import messagebox
from aes_utils import generate_key, encrypt_message, decrypt_message
from sms_sender import generate_otp, send_sms

#  Add your phone number here (used to simulate SMS)
receiver_number = "+254793967745"  # Replace with your own number for testing


# Create main window
window = tk.Tk()
window.title("Secure AES Communicator")
window.geometry("500x500")

# Message input
tk.Label(window, text="Enter your message:").pack()
message_entry = tk.Text(window, height=5, width=50)
message_entry.pack()

# Encrypt & Send button (to be linked later)
encrypt_btn = tk.Button(window, text="Encrypt & Send")
encrypt_btn.pack()


# Encrypted message input
tk.Label(window, text="Paste encrypted message here:").pack()
encrypted_text = tk.Text(window, height=5, width=50)
encrypted_text.pack()

# OTP input
tk.Label(window, text="Enter OTP:").pack()
otp_entry = tk.Entry(window)
otp_entry.pack()

# Decrypt button (to be linked later)
decrypt_btn = tk.Button(window, text="Decrypt")
decrypt_btn.pack()



# Output area
output_label = tk.Label(window, text="Decrypted message:")
output_label.pack()

def handle_decrypt():
    encrypted_msg = encrypted_text.get("1.0", tk.END).strip()
    input_otp = otp_entry.get().strip()

    #  Step 1: Check if encrypted message and OTP were entered
    if not encrypted_msg:
        messagebox.showerror("Error", "Please paste the encrypted message.")
        return

    if not input_otp:
        messagebox.showerror("Error", "Please enter the OTP.")
        return

    #  Step 2: Verify OTP matches the one generated earlier
    if input_otp != getattr(window, 'otp', None):
        messagebox.showerror("Error", "Invalid OTP.")
        return

    try:
        #  Step 3: Try decrypting using the stored AES key
        decrypted = decrypt_message(window.key, encrypted_msg)
        output_label.config(text=f"Decrypted message: {decrypted}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

def handle_encrypt():
    message = message_entry.get("1.0", tk.END).strip()

    if not message:
        messagebox.showerror("Error", "Please enter a message.")
        return

    key = generate_key()
    encrypted = encrypt_message(key, message)
    otp = generate_otp()

    # Store key and OTP for decryption
    window.key = key
    window.otp = otp

    # Simulate sending SMS
    send_sms(receiver_number, otp)

    # Show encrypted message in the box
    encrypted_text.delete("1.0", tk.END)
    encrypted_text.insert(tk.END, encrypted)

    messagebox.showinfo("Message Encrypted", "Encryption complete. OTP sent via SMS.")
    
encrypt_btn.config(command=handle_encrypt)

decrypt_btn.config(command=handle_decrypt)
# Run the app
window.mainloop()

