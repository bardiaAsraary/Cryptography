import sys
import os
import getpass  
from utils.hashing import generate_checksum, verify_checksum
from utils.crypto import encrypt_file, decrypt_file
from utils.helpers import get_password

def get_valid_file(prompt):
    """Get valid file path from user"""
    while True:
        path = input(prompt).strip()
        if os.path.exists(path):
            return path
        print(f"❌ Error: File '{path}' not found")

def main():
    print("\n" + "🔒" * 40)
    print("QUANTUM-RESISTANT FILE TOOL".center(80))
    print("🔒" * 40)
    
    while True:
        print("\nMAIN MENU:")
        print("1. Generate checksum (SHA-256/SHA3/MD5)")
        print("2. Verify checksum")
        print("3. Encrypt file (quantum-resistant)")
        print("4. Decrypt file")
        print("5. Exit")
        
        choice = input("\nChoose an option (1-5): ").strip()

        try:
            if choice == "1":
                print("\n" + "-" * 40)
                print("CHECKSUM GENERATION")
                file = get_valid_file("Enter file path: ")
                algo = input("Algorithm (sha256/sha3/md5): ").lower()
                if algo not in ("sha256", "sha3", "md5"):
                    algo = "sha256"
                    print("⚠️ Defaulting to SHA-256")
                checksum = generate_checksum(file, algo)
                print(f"\n{algo.upper()} checksum: {checksum}")
                
            elif choice == "2":
                print("\n" + "-" * 40)
                print("FILE VERIFICATION")
                file = get_valid_file("Enter file path: ")
                expected_hash = input("Enter expected hash: ").strip()
                algo = input("Algorithm (sha256/sha3/md5): ").lower()
                if verify_checksum(file, expected_hash, algo):
                    print("\n✅ Checksum verified! File is intact.")
                else:
                    print("\n❌ Checksum mismatch! File may be corrupted.")
                    
            elif choice == "3":
                print("\n" + "-" * 40)
                print("QUANTUM-RESISTANT ENCRYPTION")
                print("Uses AES-256 with scrypt KDF (resists quantum brute-force)")
                file = get_valid_file("Enter file to encrypt: ")
                password = get_password()
                encrypted_path = encrypt_file(file, password)
                if encrypted_path:
                    checksum = generate_checksum(file, "sha3")
                    print(f"\n🔐 Original file SHA3-256: {checksum}")
                    
            elif choice == "4":
                print("\n" + "-" * 40)
                print("FILE DECRYPTION")
                file = get_valid_file("Enter encrypted file: ")
                password = getpass.getpass("Enter decryption password: ").strip()
                decrypted_path = decrypt_file(file, password)
                if decrypted_path:
                    if input("Verify checksum? (y/n): ").lower() == 'y':
                        expected_hash = input("Enter original SHA3-256 hash: ").strip()
                        if verify_checksum(decrypted_path, expected_hash, "sha3"):
                            print("✅ File integrity verified!")
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