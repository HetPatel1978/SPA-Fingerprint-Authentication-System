import socket
import time
from cryptography.fernet import Fernet

SECRET_KEY = b'YOUR_SECRET_32_BYTE_KEY'  

def decrypt_data(encrypted_data):
    cipher = Fernet(SECRET_KEY)
    return cipher.decrypt(encrypted_data).decode()

def handle_spa_knock():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.bind(("0.0.0.0", 9090))
        data, _ = udp_socket.recvfrom(1024)
        return data

def forward_to_spa_server(username, timestamp, fingerprint):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("SPA_SERVER_IP", 7070))
        s.sendall(f"{username}:{timestamp}:{fingerprint.decode()}".encode())

if __name__ == "__main__":
    while True:
        data = handle_spa_knock()
        decrypted_data = decrypt_data(data)
        username, timestamp = decrypted_data.split(":")
        
        if int(time.time()) - int(timestamp) > 60:
            print("SPA Knock expired. Rejecting.")
        else:
            print(f"Valid SPA Knock from {username}. Waiting for fingerprint authentication...")
