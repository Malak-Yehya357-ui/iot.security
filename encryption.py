"""
Encryption Module with 3 Algorithms: AES-256, RSA-2048, ChaCha20-Poly1305
"""

import base64
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class EncryptionAlgorithms:
    
    @staticmethod
    def aes_encrypt(plaintext: str, key: bytes = None) -> dict:
        if key is None:
            key = get_random_bytes(32)
        
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'key': base64.b64encode(key).decode('utf-8'),
            'algorithm': 'AES-256'
        }
    
    @staticmethod
    def aes_decrypt(ciphertext_b64: str, iv_b64: str, key_b64: str) -> str:
        key = base64.b64decode(key_b64)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted_padded, AES.block_size)
        
        return decrypted.decode('utf-8')
    
    @staticmethod
    def generate_rsa_keys() -> dict:
        key = RSA.generate(2048)
        return {
            'private_key': key.export_key().decode('utf-8'),
            'public_key': key.publickey().export_key().decode('utf-8')
        }
    
    @staticmethod
    def rsa_encrypt(plaintext: str, public_key_pem: str) -> dict:
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(public_key)
        
        max_size = 245
        if len(plaintext) > max_size:
            plaintext = plaintext[:max_size]
        
        ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'algorithm': 'RSA-2048'
        }
    
    @staticmethod
    def rsa_decrypt(ciphertext_b64: str, private_key_pem: str) -> str:
        private_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(private_key)
        ciphertext = base64.b64decode(ciphertext_b64)
        decrypted = cipher.decrypt(ciphertext)
        
        return decrypted.decode('utf-8')
    
    @staticmethod
    def chacha_encrypt(plaintext: str, key: bytes = None) -> dict:
        if key is None:
            key = ChaCha20Poly1305.generate_key()
        
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, plaintext.encode('utf-8'), b'')
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'key': base64.b64encode(key).decode('utf-8'),
            'algorithm': 'ChaCha20-Poly1305'
        }
    
    @staticmethod
    def chacha_decrypt(ciphertext_b64: str, nonce_b64: str, key_b64: str) -> str:
        key = base64.b64decode(key_b64)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        
        cipher = ChaCha20Poly1305(key)
        decrypted = cipher.decrypt(nonce, ciphertext, b'')
        
        return decrypted.decode('utf-8')