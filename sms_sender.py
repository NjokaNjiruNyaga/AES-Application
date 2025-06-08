import africastalking
import random

# ✅ Africa's Talking credentials (use sandbox credentials for testing)
username = "sandbox"  # use 'sandbox' for testing
api_key = "atsk_4bbb872bad0e91483f82a0c1586b1ea39aa3bb7dbcda637e254228586abb45db4f0a2f0e"  # replace with your API key

# ✅ Initialize Africa's Talking
africastalking.initialize(username, api_key)
sms = africastalking.SMS

# ✅ OTP Generator
def generate_otp():
    return str(random.randint(100000, 999999))

# ✅ Send SMS Function
def send_sms(phone_number, otp):
    message = f"Your AES App OTP is: {otp}"
    try:
        response = sms.send(message, [phone_number])
        print("[AFRICASTALKING] OTP sent successfully:", response)
        return True
    except Exception as e:
        print("[AFRICASTALKING] SMS sending failed:", str(e))
        return False
