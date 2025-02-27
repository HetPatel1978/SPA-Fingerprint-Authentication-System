import socket
import hashlib
import os
import base64
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import subprocess  # For fingerprint capture

# Server Configuration
INTERMEDIATE_SERVER_IP = "192.168.1.50"  # Intermediate Server IP
SPA_SERVER_IP = "192.168.1.100"  # SPA Server IP
TCP_PORT = 7070
UDP_PORT = 9090

# Encryption Key (Must be shared across SPA components)
SECRET_KEY = b'YOUR_32_BYTE_SECRET_KEY'  

# Generate a random IV (Initialization Vector) for encryption
def generate_iv():
    return os.urandom(16)

# AES Encryption Function
def encrypt_data(data, iv):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted_data).decode()

# Function to capture fingerprint and generate a secure hash
def get_fingerprint_hash():
    """Captures fingerprint and returns hashed fingerprint"""
    print("Please scan your fingerprint...")
    result = os.popen("fprintd-verify $USER").read()  # Uses Linux `fprintd`

    if "verify-match" in result:
        fingerprint_data = "UserAuthenticated"
        fingerprint_hash = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        return fingerprint_hash
    else:
        print("Fingerprint authentication failed.")
        return None

# Send an encrypted SPA knock (UDP packet)
def send_spa_knock(username):
    timestamp = str(int(time.time()))
    data = f"{username}:{timestamp}"
    
    iv = generate_iv()
    encrypted_payload = encrypt_data(data, iv)
    
    print(f"Sending SPA Knock: {encrypted_payload}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(encrypted_payload.encode(), (INTERMEDIATE_SERVER_IP, UDP_PORT))

# Send fingerprint hash over TCP if SPA knock is successful
def send_fingerprint(fingerprint_hash):
    iv = generate_iv()
    encrypted_fingerprint = encrypt_data(fingerprint_hash, iv)

    message = f"FingerprintHash:{encrypted_fingerprint}"
    
    print(f"Sending Fingerprint Hash: {message}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SPA_SERVER_IP, TCP_PORT))
        sock.sendall(message.encode())
        response = sock.recv(1024).decode()
        print(f"Server Response: {response}")

# === Client Workflow ===
username = os.getlogin()  # Get the system's current user

send_spa_knock(username)  # Send initial SPA Knock
time.sleep(1)  # Wait for a response from the Intermediate Server

fingerprint_hash = get_fingerprint_hash()  # Capture fingerprint
if fingerprint_hash:
    send_fingerprint(fingerprint_hash)  # Send for authentication
    print("Authentication request sent successfully.")
else:
    print("Fingerprint authentication failed.")
