#!/usr/bin/env python3
"""
Test file with Cryptography and Secrets vulnerabilities
This file contains intentional security vulnerabilities for testing purposes.
DO NOT use this code in production!
"""

import hashlib
import random
import requests
from Crypto.Cipher import DES, ARC4
import base64

class WeakCryptography:
    def hash_password(self, password):
        # VULNERABILITY: Weak hashing - MD5
        return hashlib.md5(password.encode()).hexdigest()
    
    def hash_data(self, data):
        # VULNERABILITY: Weak hashing - SHA1
        return hashlib.sha1(data.encode()).hexdigest()
    
    def encrypt_data(self, data, key):
        # VULNERABILITY: Weak encryption - DES
        cipher = DES.new(key, DES.MODE_ECB)
        padded_data = data + ' ' * (8 - len(data) % 8)
        return cipher.encrypt(padded_data.encode())
    
    def encrypt_message(self, message, key):
        # VULNERABILITY: Weak encryption - RC4/ARC4
        cipher = ARC4.new(key)
        return cipher.encrypt(message.encode())
    
    def generate_token(self):
        # VULNERABILITY: Weak random - predictable
        return str(random.randint(100000, 999999))
    
    def create_session_id(self):
        # VULNERABILITY: Weak random - time-based
        import time
        return hashlib.md5(str(time.time()).encode()).hexdigest()

class HardcodedSecrets:
    # VULNERABILITY: Hardcoded API key (sanitized dummy value to avoid real secret pattern)
    API_KEY = "sk_demo_PLACEHOLDER_KEY_NOT_REAL"
    
    # VULNERABILITY: Hardcoded database password
    DB_PASSWORD = "SuperSecret123!"
    
    # VULNERABILITY: Hardcoded AWS credentials
    AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    
    def connect_to_database(self):
        # VULNERABILITY: Hardcoded credentials in connection string
        connection_string = "postgresql://admin:password123@localhost:5432/mydb"
        return connection_string
    
    def send_email(self, recipient, message):
        # VULNERABILITY: Hardcoded SMTP credentials
        smtp_user = "admin@example.com"
        smtp_pass = "EmailPass2024!"
        return f"Sending email with {smtp_user}:{smtp_pass}"
    
    def call_api(self, endpoint):
        # VULNERABILITY: Hardcoded API token in header
        headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret_token_here",
            "X-API-Key": "1234567890abcdef"
        }
        return requests.get(endpoint, headers=headers)

class InsecureAuthentication:
    def verify_password(self, user_password, stored_password):
        # VULNERABILITY: Plain text password comparison
        return user_password == stored_password
    
    def store_password(self, password):
        # VULNERABILITY: Storing password in plain text
        with open("passwords.txt", "a") as f:
            f.write(password + "\n")
    
    def create_jwt_token(self, user_id):
        # VULNERABILITY: Weak JWT secret
        secret = "secret"
        payload = {"user_id": user_id}
        # Simplified JWT creation (vulnerable)
        return base64.b64encode(str(payload).encode()).decode()
    
    def generate_reset_token(self, email):
        # VULNERABILITY: Predictable reset token
        return hashlib.md5(email.encode()).hexdigest()

class InsecureNetwork:
    def fetch_data(self, url):
        # VULNERABILITY: Disabled SSL verification
        response = requests.get(url, verify=False)
        return response.text
    
    def download_file(self, url):
        # VULNERABILITY: HTTP instead of HTTPS
        file_url = url.replace("https://", "http://")
        return requests.get(file_url)
    
    def connect_to_service(self, host):
        # VULNERABILITY: Insecure protocol
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, 23))  # Telnet port
        return sock

class PrivateKeyExposure:
    # VULNERABILITY: Hardcoded private key
    PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----"""
    
    # VULNERABILITY: Hardcoded SSH key
    SSH_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDExample user@host"
    
    def get_encryption_key(self):
        # VULNERABILITY: Hardcoded encryption key
        return b"ThisIsMySecretEncryptionKey123!"
