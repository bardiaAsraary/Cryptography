import hashlib

def generate_checksum(file_path, algorithm="sha256"):
    """Generate checksum for a file using SHA-256 or MD5."""
    hash_func = hashlib.sha256() if algorithm == "sha256" else hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def verify_checksum(file_path, expected_hash, algorithm="sha256"):
    """Verify if file matches the expected hash."""
    computed_hash = generate_checksum(file_path, algorithm)
    return computed_hash == expected_hash