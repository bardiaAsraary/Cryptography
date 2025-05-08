import re
import getpass  # For secure password input

def get_password():
    """Get password with confirmation and masking"""
    while True:
        pwd = getpass.getpass("Enter password: ").strip()
        confirm = getpass.getpass("Confirm password: ").strip()
        
        if pwd == confirm:
            if is_strong_password(pwd):
                return pwd
            print("⚠️ Password too weak (see requirements below)")
        else:
            print("❌ Passwords don't match!")
        
        print("Password must contain:")
        print("- 8+ characters")
        print("- Uppercase and lowercase letters")
        print("- At least one number")

def is_strong_password(pwd: str) -> bool:
    """Check password meets strength requirements"""
    return (
        len(pwd) >= 8 and
        re.search(r"[A-Z]", pwd) and  # Uppercase
        re.search(r"[a-z]", pwd) and  # Lowercase
        re.search(r"\d", pwd)         # Digit
    )