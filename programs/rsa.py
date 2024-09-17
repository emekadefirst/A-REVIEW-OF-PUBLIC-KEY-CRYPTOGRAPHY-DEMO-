from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
from Crypto.Random import get_random_bytes

# def rsa_encrypt(message, public_key_path='public_key.pem'):
#     with open(public_key_path, 'rb') as pub_file:
#         public_key = RSA.import_key(pub_file.read())
#     cipher_rsa = PKCS1_OAEP.new(public_key)
#     encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))
#     return encrypted_message


def rsa_encrypt(message, public_key_str):
    public_key = RSA.import_key(public_key_str)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher_rsa.encrypt(message.encode("utf-8"))
    return base64.b64encode(encrypted_message).decode(
        "utf-8"
    )  


def rsa_decrypt(encrypted_message, private_key_path='private_key.pem'):
    with open(private_key_path, 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(encrypted_message).decode('utf-8')
    return decrypted_message
