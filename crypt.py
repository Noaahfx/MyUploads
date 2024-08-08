from cryptography.fernet import Fernet

# Generate a key
key = Fernet.generate_key()
print(f"Key: {key.decode()}")

# Store the key securely
