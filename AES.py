from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
import os

def aes_encrypt(shared_key, plaintext):
    # Ensure the shared key is 256 bits long
    key = shared_key[:32]  # Use the first 256 bits (32 bytes) of the shared key

    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)  # AES block size is 128 bits (16 bytes)

    # Create a cipher object with AES-256 and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Add padding to the plaintext to make it a multiple of the block size (128 bits)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the data
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    print("encrypted: ",iv+ciphertext)
    print(type(iv+ciphertext))
    # Return the ciphertext and the IV (IV must be sent with the ciphertext)
    return iv + ciphertext

def aes_decrypt(shared_key, ciphertext):
    # Ensure the shared key is 256 bits long
    key = shared_key[:32]  # Use the first 256 bits (32 bytes) of the shared key

    # Extract the IV from the beginning of the ciphertext
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    # Create a cipher object with AES-256 and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Decrypt the data
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding from the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    print(plaintext.decode())
    return plaintext.decode()
