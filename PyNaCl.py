import nacl.secret
import nacl.utils
from nacl.encoding import Base64Encoder


def encrypt(message, key):
    box = nacl.secret.SecretBox(key)
    encrypted = box.encrypt(message.encode(), encoder=Base64Encoder)
    return encrypted.decode('utf-8')

def decrypt(encrypted_message, key):
    box = nacl.secret.SecretBox(key)
    decrypted = box.decrypt(encrypted_message.encode(), encoder=Base64Encoder)
    return decrypted.decode('utf-8')

if __name__ == "__main__":
    # Generate a random key
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    print("Generated key:", key)

    login_credentials = {'username': 'my_username', 'password': 'my_password'}

    # Encrypting the login credentials
    encrypted_credentials = encrypt(str(login_credentials), key)
    print("Encrypted credentials:", encrypted_credentials)

    # Decrypting the login credentials
    decrypted_credentials = decrypt(encrypted_credentials, key)
    print("Decrypted credentials:", decrypted_credentials)
