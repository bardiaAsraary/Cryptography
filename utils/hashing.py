import hashlib
from Crypto.Hash import SHA3_256

def generate_checksum(file_path, algorithm="sha256"):
    if algorithm == "sha3":
        sha3 = SHA3_256.new()
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha3.update(chunk)
        return sha3.hexdigest()
    else:
        hash_func = hashlib.sha256() if algorithm == "sha256" else hashlib.md5()
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest()

def verify_checksum(file_path, expected_hash, algorithm="sha256"):
    return generate_checksum(file_path, algorithm) == expected_hash