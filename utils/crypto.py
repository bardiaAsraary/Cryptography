import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path, password):
    try:
        salt = os.urandom(16)
        key = generate_key(password, salt)
        fernet = Fernet(key)
        
        with open(file_path, "rb") as f:
            data = f.read()
            
        encrypted_data = fernet.encrypt(data)
        output_path = f"encrypted/{os.path.basename(file_path)}.enc"
        os.makedirs("encrypted", exist_ok=True)
        
        with open(output_path, "wb") as f:
            f.write(salt + encrypted_data)
            
        print(f"✅ File encrypted to {output_path}")
        return output_path
        
    except Exception as e:
        print(f"❌ Encryption failed: {str(e)}")
        return None

# THIS IS THE CRITICAL FUNCTION THAT MUST BE PRESENT
def decrypt_file(encrypted_path, password):
    try:
        with open(encrypted_path, "rb") as f:
            file_content = f.read()
            
        salt = file_content[:16]
        encrypted_data = file_content[16:]
        
        key = generate_key(password, salt)
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        output_path = f"decrypted/{os.path.basename(encrypted_path).replace('.enc', '')}"
        os.makedirs("decrypted", exist_ok=True)
        
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
            
        print(f"✅ File decrypted to {output_path}")
        return output_path
        
    except Exception as e:
        print(f"❌ Decryption failed: {str(e)}")
        return None