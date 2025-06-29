import tkinter as tk
from tkinter import messagebox
from aes_utils import generate_key, encrypt_message, decrypt_message
from sms_sender import generate_otp, send_sms

# Create the main landing window
window = tk.Tk()
window.title("Secure AES Communication Portal")
window.geometry("600x650")
window.configure(bg="white")

# === STYLES ===
HEADER_FONT = ("Arial", 16, "bold")
LABEL_FONT = ("Arial", 12)

# === UI Elements ===
tk.Label(window, text="🔐 Secure AES Communication", font=HEADER_FONT, bg="white").pack(pady=10)

# === Message Entry ===
tk.Label(window, text="Enter Message to Encrypt:", font=LABEL_FONT, bg="white").pack()
message_frame = tk.Frame(window, bg="white", padx=10, pady=5)
message_frame.pack()
message_entry = tk.Text(message_frame, height=5, width=70, bd=2, relief="solid")
message_entry.pack()

# === Encrypted Message Display ===
tk.Label(window, text="Encrypted Message:", font=LABEL_FONT, bg="white").pack()
encrypted_frame = tk.Frame(window, bg="white", padx=10, pady=5)
encrypted_frame.pack()
encrypted_text = tk.Text(encrypted_frame, height=5, width=70, bd=2, relief="solid")
encrypted_text.pack()

# === OTP Input ===
tk.Label(window, text="Enter OTP:", font=LABEL_FONT, bg="white").pack()
otp_frame = tk.Frame(window, bg="white", padx=10, pady=5)
otp_frame.pack()
otp_entry = tk.Entry(otp_frame, width=30, bd=2, relief="solid")
otp_entry.pack()

# === Output ===
tk.Label(window, text="Decrypted Message:", font=LABEL_FONT, bg="white").pack()
output_frame = tk.Frame(window, bg="white", padx=10, pady=5)
output_frame.pack()
output_box = tk.Text(output_frame, height=5, width=70, bd=2, relief="solid")
output_box.pack()

# === Backend Variables ===
receiver_number = "+254793967745"  # Replace with your real number (for live mode)

# === Encrypt and Send OTP ===
def handle_encrypt():
    message = message_entry.get("1.0", tk.END).strip()
    if not message:
        messagebox.showerror("Error", "Message cannot be empty")
        return

    key = generate_key()
    encrypted = encrypt_message(key, message)
    otp = generate_otp()

    window.key = key
    window.otp = otp

    encrypted_text.delete("1.0", tk.END)
    encrypted_text.insert(tk.END, encrypted)

    if send_sms(receiver_number, otp):
        messagebox.showinfo("OTP Sent", f"OTP has been sent to {receiver_number}")
    else:
        messagebox.showerror("SMS Failed", "Could not send OTP. Check credentials or API key.")

# === Decrypt ===
def handle_decrypt():
    encrypted_msg = encrypted_text.get("1.0", tk.END).strip()
    input_otp = otp_entry.get().strip()

    if not encrypted_msg:
        messagebox.showerror("Error", "Paste the encrypted message.")
        return
    if not input_otp:
        messagebox.showerror("Error", "Enter the OTP sent to your phone.")
        return
    if input_otp != getattr(window, 'otp', None):
        messagebox.showerror("Error", "Incorrect OTP.")
        return

    try:
        decrypted = decrypt_message(window.key, encrypted_msg)
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, decrypted)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

# === Buttons ===
tk.Button(window, text="🔐 Encrypt & Send OTP", command=handle_encrypt, bg="#4CAF50", fg="white", width=30).pack(pady=10)
tk.Button(window, text="🔓 Decrypt Message", command=handle_decrypt, bg="#2196F3", fg="white", width=30).pack(pady=5)

# === Start GUI ===
window.mainloop()
