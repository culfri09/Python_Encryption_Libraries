from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

def pad(data):
    padding_length = AES.block_size - (len(data) % AES.block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt(message, key):
    message = pad(message.encode())
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(message)
    return b64encode(iv + ciphertext).decode()

def decrypt(encrypted_message, key):
    encrypted_message = b64decode(encrypted_message.encode())
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(ciphertext)
    return unpad(decrypted_message).decode()

if __name__ == "__main__":
    # Generate a random key
    key = get_random_bytes(16)
    print(key)
    login_credentials = {'username': 'my_username', 'password': 'my_password'}

    # Encrypting the login credentials
    encrypted_credentials = encrypt(str(login_credentials), key)
    print("Encrypted credentials:", encrypted_credentials)

    # Decrypting the login credentials
    decrypted_credentials = decrypt(encrypted_credentials, key)
    print("Decrypted credentials:", decrypted_credentials)
