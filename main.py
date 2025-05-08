import sys
import os
import getpass
import re
from utils.hashing import generate_checksum, verify_checksum
from utils.crypto import encrypt_file, decrypt_file

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def get_secure_password():
    """Get password with confirmation and strength checks"""
    while True:
        pwd = getpass.getpass("Enter password: ").strip()
        confirm = getpass.getpass("Confirm password: ").strip()
        
        if pwd != confirm:
            print("❌ Passwords don't match! Try again.")
            continue
            
        if len(pwd) < 8:
            print("⚠️ Password must be at least 8 characters")
            continue
            
        if not re.search(r"[A-Z]", pwd):
            print("⚠️ Password must contain at least one uppercase letter")
            continue
            
        if not re.search(r"[a-z]", pwd):
            print("⚠️ Password must contain at least one lowercase letter")
            continue
            
        if not re.search(r"\d", pwd):
            print("⚠️ Password must contain at least one number")
            continue
            
        return pwd

def get_valid_file(prompt):
    """Get valid file path from user"""
    while True:
        path = input(prompt).strip()
        if os.path.exists(path):
            return path
        print(f"❌ Error: File '{path}' not found")

def main():
    print("\n" + "🔒" * 40)
    print("SECURE FILE TOOL".center(80))
    print("🔒" * 40)
    
    while True:
        print("\nMAIN MENU:")
        print("1. Generate checksum (SHA-256/MD5)")
        print("2. Verify checksum")
        print("3. Encrypt file")
        print("4. Decrypt file")
        print("5. Exit")
        
        choice = input("\nChoose an option (1-5): ").strip()

        try:
            if choice == "1":
                print("\n" + "-" * 40)
                print("CHECKSUM GENERATION")
                file = get_valid_file("Enter file path: ")
                algo = input("Algorithm (sha256/md5): ").lower()
                if algo not in ("sha256", "md5"):
                    algo = "sha256"
                    print("⚠️ Defaulting to SHA-256")
                checksum = generate_checksum(file, algo)
                print(f"\n{algo.upper()} checksum: {checksum}")
                
            elif choice == "2":
                print("\n" + "-" * 40)
                print("FILE VERIFICATION")
                file = get_valid_file("Enter file path: ")
                expected_hash = input("Enter expected hash: ").strip()
                algo = input("Algorithm (sha256/md5): ").lower()
                if verify_checksum(file, expected_hash, algo):
                    print("\n✅ Checksum verified! File is intact.")
                else:
                    print("\n❌ Checksum mismatch! File may be corrupted.")
                    
            elif choice == "3":
                print("\n" + "-" * 40)
                print("FILE ENCRYPTION")
                print("Password requirements:")
                print("- 8+ characters")
                print("- Upper and lowercase letters")
                print("- At least one number")
                
                file = get_valid_file("Enter file to encrypt: ")
                password = get_secure_password()
                
                encrypted_path = encrypt_file(file, password)
                if encrypted_path:
                    checksum = generate_checksum(file)
                    print(f"\n🔐 Encryption successful!")
                    print(f"📁 Encrypted file: {encrypted_path}")
                    print(f"🔢 Original checksum (SHA-256): {checksum}")
                    print("⚠️ Save this checksum to verify after decryption!")
                    
            elif choice == "4":
                print("\n" + "-" * 40)
                print("FILE DECRYPTION")
                file = get_valid_file("Enter encrypted file: ")
                password = getpass.getpass("Enter decryption password: ").strip()
                
                decrypted_path = decrypt_file(file, password)
                if decrypted_path:
                    print(f"\n🔓 Decryption successful!")
                    print(f"📁 Decrypted file: {decrypted_path}")
                    
                    if input("Verify against original checksum? (y/n): ").lower() == 'y':
                        expected_hash = input("Enter original checksum: ").strip()
                        if verify_checksum(decrypted_path, expected_hash):
                            print("✅ Decrypted file matches original!")
                        else:
                            print("❌ WARNING: File may be corrupted!")
                            
            elif choice == "5":
                print("\n🔒 Exiting...")
                break
                
            else:
                print("❌ Invalid choice. Please enter 1-5.")
                
        except KeyboardInterrupt:
            print("\n⚠️ Operation cancelled.")
        except Exception as e:
            print(f"\n❌ Error: {str(e)}")
            
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()