import os
import random
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Encryption:

    @staticmethod
    def generate_rsa_keys():
        """Generate a pair of RSA private and public keys."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def generate_verification_code():
        """Generate a 6-digit verification code."""
        return str(random.randint(100000, 999999))

    @staticmethod
    def sign_data(private_key, data):
        """Create a digital signature for the data using the private key."""
        signature = private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify_signature(public_key, data, signature):
        """Verify the signature using the public key."""
        try:
            public_key.verify(
                signature,
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            print("Invalid signature.")
            return False
        except Exception as e:
            print(f"An error occurred: {e}")
            return False

    @staticmethod
    def encrypt_private_key(salt: bytes, iv: bytes, password: bytes, private_key_pem: bytes) -> str:
        """Encrypt the private key using AES and return the encrypted private key, IV, salt, and password."""
        # Derive the encryption key from the password and salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        encryption_key = kdf.derive(password)

        # AES encryption
        cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(private_key_pem) + encryptor.finalize()

        # Return the encrypted private key along with IV, salt, and password as a concatenated string
        return f"{salt.hex()}|{iv.hex()}|{encrypted_data.hex()}"

    @staticmethod
    def decrypt_private_key(salt: bytes, iv: bytes, encrypted_data: bytes, password: bytes) -> bytes:
        """Decrypt the private key using AES."""
        # Derive the decryption key from the password and salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        decryption_key = kdf.derive(password)

        # AES decryption
        cipher = Cipher(algorithms.AES(decryption_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        return decrypted_data

    @staticmethod
    def generate_aes_key():
        """Generate a random 256-bit AES key."""
        return os.urandom(32)

    @staticmethod
    def encrypt_aes_key_with_rsa(aes_key, recipient_public_key):
        """Encrypt an AES key using the recipient's RSA public key."""
        encrypted_aes_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_aes_key

    @staticmethod
    def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key):
        """Decrypt an AES key using the recipient's RSA private key."""
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key

    @staticmethod
    def encrypt_message_aes(key, plaintext):
        """Encrypt a plaintext message using AES in GCM mode."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return iv, ciphertext, encryptor.tag

    @staticmethod
    def decrypt_message_aes(key, iv, ciphertext, tag):
        """Decrypt a ciphertext message using AES in GCM mode."""
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


