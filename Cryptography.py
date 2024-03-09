from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

def encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + ciphertext).decode('utf-8')

def decrypt(encrypted_message, key):
    encrypted_message = base64.urlsafe_b64decode(encrypted_message.encode('utf-8'))
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode('utf-8')

if __name__ == "__main__":
    # Generate a random key
    password = b'password'
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    print("Derived key:", key)

    login_credentials = {'username': 'my_username', 'password': 'my_password'}

    # Encrypting the login credentials
    encrypted_credentials = encrypt(str(login_credentials), key)
    print("Encrypted credentials:", encrypted_credentials)

    # Decrypting the login credentials
    decrypted_credentials = decrypt(encrypted_credentials, key)
    print("Decrypted credentials:", decrypted_credentials)
