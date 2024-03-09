import logging
import nacl.secret
import nacl.utils
from nacl.encoding import Base64Encoder
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import time
import sys

# Configure file logging
logging.basicConfig(filename='libraries.log', encoding='utf-8', level=logging.DEBUG)
logger = logging.getLogger('test')

# PyNaCl methods
def nacl_encrypt(message, key):
    box = nacl.secret.SecretBox(key)
    encrypted = box.encrypt(message.encode(), encoder=Base64Encoder)
    return encrypted.decode('utf-8')

def nacl_decrypt(encrypted_message, key):
    box = nacl.secret.SecretBox(key)
    decrypted = box.decrypt(encrypted_message.encode(), encoder=Base64Encoder)
    return decrypted.decode('utf-8')

# PyCryptodome methods
def pad(data):
    padding_length = AES.block_size - (len(data) % AES.block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def pycryptodome_encrypt(message, key):
    message = pad(message.encode())
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(message)
    return b64encode(iv + ciphertext).decode()

def pycryptodome_decrypt(encrypted_message, key):
    encrypted_message = b64decode(encrypted_message.encode())
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(ciphertext)
    return unpad(decrypted_message).decode()

# Cryptography methods
def cryptography_encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + ciphertext).decode('utf-8')

def cryptography_decrypt(encrypted_message, key):
    encrypted_message = base64.urlsafe_b64decode(encrypted_message.encode('utf-8'))
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode('utf-8')

# Main function
if __name__ == "__main__":
    company_name = {'Organizaciones inteligentes'}

    '''PyNaCl Encryption'''
    # Generate a random key
    nacl_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    logger.info("PyNaCl Key: %s", nacl_key)
    logger.info("PyNaCl Key Length: %s", len(nacl_key))

    # Encrypting 
    start_time = time.time()
    nacl_encrypted_name = nacl_encrypt(str(company_name),  nacl_key)
    logger.info("PyNaCl Encrypted Message: %s", nacl_encrypted_name)
    logger.info("PyNaCl Encrypted Message Length: %s", len(nacl_encrypted_name))
    end_time = time.time()
    logger.info("PyNaCl Encryption Time: %s seconds", end_time - start_time)

    # Decrypting 
    nacl_decrypted_name = nacl_decrypt(nacl_encrypted_name, nacl_key)
    logger.info("PyNaCl Decrypted Message: %s", nacl_decrypted_name)

    '''PyCryptodome Encryption'''
    pycryptodome_key = get_random_bytes(16)
    logger.info("PyCryptodome Key: %s", pycryptodome_key)
    logger.info("PyCryptodome Key Length: %s", len(pycryptodome_key))

    start_time = time.time()
    pycryptodome_encrypted_name = pycryptodome_encrypt(str(company_name),  pycryptodome_key)
    logger.info("PyCryptodome Encrypted Message: %s", pycryptodome_encrypted_name)
    logger.info("PyCryptodome Encrypted Message Length: %s", len(pycryptodome_encrypted_name))
    end_time = time.time()
    logger.info("PyCryptodome Encryption Time: %s seconds", end_time - start_time)
    
    pycryptodome_decrypted_name = pycryptodome_decrypt(pycryptodome_encrypted_name, pycryptodome_key)
    logger.info("PyCryptodome Decrypted Message: %s", pycryptodome_decrypted_name)

    '''Cryptography Encryption'''
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
    cryptography_key = kdf.derive(password)
    logger.info("Cryptography Key Length: %s", len(cryptography_key))

    start_time = time.time()
    cryptography_encrypted_name = cryptography_encrypt(str(company_name),  cryptography_key)
    logger.info("Cryptography Encrypted Message: %s", cryptography_encrypted_name)
    logger.info("Cryptography Encrypted Message Length: %s", len(cryptography_encrypted_name))
    end_time = time.time()
    logger.info("Cryptography Encryption Time: %s seconds", end_time - start_time)

    cryptography_decrypted_name = cryptography_decrypt(cryptography_encrypted_name, cryptography_key)
    logger.info("Cryptography Decrypted Message: %s", cryptography_decrypted_name)

