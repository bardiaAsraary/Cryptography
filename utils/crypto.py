import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def hybrid_encrypt(data: bytes, password: str) -> bytes:
    """Quantum-resistant hybrid encryption (AES-GCM + strong KDF)"""
    # 1. Generate random salt
    salt = get_random_bytes(16)
    
    # 2. Derive key using strong KDF (resist brute-force)
    key = scrypt(password, salt, key_len=32, N=2**20, r=8, p=1)
    
    # 3. Encrypt with AES-GCM
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    # Format: [salt][nonce][tag][ciphertext]
    return salt + cipher.nonce + tag + ciphertext

def hybrid_decrypt(encrypted: bytes, password: str) -> bytes:
    """Decrypt hybrid-encrypted data"""
    # Parse components
    salt = encrypted[:16]
    nonce = encrypted[16:32]
    tag = encrypted[32:48]
    ciphertext = encrypted[48:]
    
    # Derive key
    key = scrypt(password, salt, key_len=32, N=2**20, r=8, p=1)
    
    # Decrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def encrypt_file(file_path, password):
    try:
        os.makedirs("encrypted", exist_ok=True)
        
        with open(file_path, "rb") as f:
            data = f.read()
        
        encrypted_data = hybrid_encrypt(data, password)
        output_path = os.path.join("encrypted", f"{os.path.basename(file_path)}.pqenc")
        
        with open(output_path, "wb") as f:
            f.write(encrypted_data)
        
        print(f"✅ Encrypted (quantum-resistant) to: {output_path}")
        return output_path
    except Exception as e:
        print(f"❌ Encryption failed: {str(e)}")
        return None

def decrypt_file(encrypted_path, password):
    try:
        with open(encrypted_path, "rb") as f:
            encrypted_data = f.read()
        
        decrypted_data = hybrid_decrypt(encrypted_data, password)
        output_path = os.path.join("decrypted", os.path.basename(encrypted_path).replace('.pqenc', ''))
        
        os.makedirs("decrypted", exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
        
        print(f"✅ Decrypted to: {output_path}")
        return output_path
    except Exception as e:
        print(f"❌ Decryption failed: {str(e)}")
        return None