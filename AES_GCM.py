from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


class AES_GCM:
    def __init__(self, key:bytes):
        """
        Initialize the VPN Encryption class with a symmetric key.

        :param key: A 256-bit (32-byte) symmetric key derived from ECDH
        """
        if len(key) != 32:
            raise ValueError("Key must be 256 bits (32 bytes) long")
        self.key = key

    def encrypt(self, plaintext:bytes, aad:bytes = None) -> dict:
        """

        :param plaintext: plaintext to encrypt
        :param aad: Optional authenticated additional data
        :return: A dictionary containing the ciphertext, nonce and tag
        """
        #Generating the nonce
        nonce = os.urandom(12)

        #Creating the AES-GCM cypher
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()

        #Include AAD if given
        if aad:
            encryptor.authenticate_additional_data(aad)

        #Encrypting the plaintext
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": encryptor.tag
        }

    def decrypt(self, ciphertext:bytes, nonce:bytes, tag:bytes, aad:bytes = None) -> bytes:
        """
        :param ciphertext: Ciphertext to decrypt
        :param nonce: 96 bit nonce used during encryption
        :param tag: The authentication tag generated during encryption
        :param aad: Optional authenticated additional data
        :return: The decrypted plaintext
        """
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        if aad:
            decryptor.authenticate_additional_data(aad)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext