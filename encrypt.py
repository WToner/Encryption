from cryptography.fernet import Fernet

# Generate a key (only do this once, then share/store securely)
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt a message
def encrypt_message(message: str) -> bytes:
    return cipher.encrypt(message.encode())

# Decrypt a message
def decrypt_message(token: bytes) -> str:
    return cipher.decrypt(token).decode()

# Example usage
if __name__ == "__main__":
    message = "Hello, this is a secret message."
    encrypted = encrypt_message(message)
    decrypted = decrypt_message(encrypted)

    print("Original:", message)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)
