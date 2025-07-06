import africastalking
import random
import string

# ✅ Africa's Talking credentials (use sandbox credentials for testing)
username = "Njoks"  # use 'sandbox' for testing(Give your own explanation)
api_key = "atsk_3637a04bfad012439e75be6ff21c9152b1b03cb0263e7d40e72fbd2e8615a385b2bf3cc5"  # replace with your API key

# ✅ Initialize Africa's Talking
africastalking.initialize(username, api_key)
sms = africastalking.SMS

# This  OTP Generator
def generate_otp(length=8):
    characters = string.ascii_uppercase + string.digits  # A-Z and 0-9
    otp = ''.join(random.choices(characters, k=length))
    return otp

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
