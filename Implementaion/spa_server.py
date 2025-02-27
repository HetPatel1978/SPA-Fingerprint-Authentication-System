import socket
import hashlib
import subprocess
from cryptography.fernet import Fernet

SECRET_KEY = b'YOUR_SECRET_32_BYTE_KEY'  
VALID_FINGERPRINT_HASH = "VALID_HASH_FROM_DATABASE"

def validate_fingerprint(fingerprint):
    return hashlib.sha256(bytes.fromhex(fingerprint)).hexdigest() == VALID_FINGERPRINT_HASH

def whitelist_ip(ip):
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "ACCEPT"])

def handle_client(conn):
    data = conn.recv(1024).decode()
    username, timestamp, fingerprint = data.split(":")
    
    if validate_fingerprint(fingerprint):
        client_ip = conn.getpeername()[0]
        whitelist_ip(client_ip)
        conn.sendall(b"AUTH_GRANTED")
    else:
        conn.sendall(b"AUTH_FAILED")

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("0.0.0.0", 7070))
        server.listen()
        while True:
            conn, _ = server.accept()
            handle_client(conn)
