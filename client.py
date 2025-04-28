import os
import socket
import sys
from encryption import Encryption
from protocol import compose_packet, PacketType
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1'
PORT = 65432

client_id = input("Enter your phone number: ")

def register_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        client_socket.sendall(b"1")  # Check if the client is in db
        # Wait for server approve
        response = client_socket.recv(1024).decode()
        if "Choice approved" in response:
            pass
        else:
            print("Registration failed. Please try again.")
            return

        # Generate RSA private key and public key for the client
        private_key, public_key = Encryption.generate_rsa_keys()

        # Convert the private key to PEM
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Convert the public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # Send the registration details to server
        packet = compose_packet(PacketType.REGISTRATION, f"{client_id}|{public_key_pem}")
        client_socket.sendall(packet.encode())

        # Wait for server response
        response = client_socket.recv(1024).decode()
        print(f"Server response: {response}")

        if response == "Client already registered.":
            print("You are already registered, skipping registration.")
            return  # Return early if already registered

        # Wait for verification code
        verification_code = client_socket.recv(1024).decode()
        print(f"Received verification code: {verification_code}")

        verification_code = input(f"Enter verification code: ")

        # Sign the verification code using the private key
        signature = Encryption.sign_data(private_key, verification_code)
        client_socket.sendall(signature)  # Send the signed verification code to the server

        # Wait for verification approve
        response = client_socket.recv(1024).decode()
        if "Verification approved" in response:
            print("You are now registered!")
        else:
            print("Registration failed. Please try again.")
            return

        # Ask the user for their password
        password = input("Enter your password to decrypt your received data: ").encode()
        # Encrypt the private key, Prepare the encrypted private key with additional details
        salt = os.urandom(16)  # Random Salt
        iv = os.urandom(16)  # Random IV
        # Encrypt the private key of the client
        encrypted_private_key = Encryption.encrypt_private_key(salt, iv, password, private_key_pem)
        client_socket.sendall(encrypted_private_key.encode())

def send_message():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        client_socket.sendall(b"2")  # Indicate send message option
        # Wait for the server to approve the choice
        response = client_socket.recv(1024).decode()
        if "Choice approved" in response:
            pass
        else:
            print("Registration failed. Please try again.")
            return

        # Check if the client is in db of the server
        packet = compose_packet(PacketType.MESSAGE, f"{client_id}")
        client_socket.sendall(packet.encode())
        response = client_socket.recv(1024).decode()
        if "you registered." in response:
            pass
        else:
            print("You must register first.")
            return

        recipient_id = input("Enter recipient phone number : ")
        client_socket.sendall(recipient_id.encode())

        # Server check if the receiver is in db of the server
        response = client_socket.recv(1024).decode()
        if "Recipient not found." in response:
            print("Recipient not found. Returning to menu.")
            return

        message = input("Enter the message to send: ")
        aes_key = Encryption.generate_aes_key()

        # Get public key of recipient from server
        recipient_public_key_pem = client_socket.recv(1024).decode()
        # Return an object of type RSAPublicKey
        recipient_public_key = serialization.load_pem_public_key(
            recipient_public_key_pem.encode()
        )

        # Encrypt AES key using the recipient's RSA public key (through Encryption class)
        encrypted_aes_key = Encryption.encrypt_aes_key_with_rsa(aes_key, recipient_public_key)
        iv, ciphertext, tag = Encryption.encrypt_message_aes(aes_key, message)
        encrypted_message = f"{encrypted_aes_key.hex()}|{iv.hex()}|{ciphertext.hex()}|{tag.hex()}"

        # Send encrypted message to the server
        client_socket.sendall(encrypted_message.encode())
        print(client_socket.recv(1024).decode())


def receive_messages():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        client_socket.sendall(b"3")  # Indicate send message option
        # Wait for the server to approve the choice
        response = client_socket.recv(1024).decode()
        if "Choice approved" in response:
            pass
        else:
            print("Registration failed. Please try again.")
            return

        # Check if the client is in db of the server
        packet = compose_packet(PacketType.CONFIRMATION, f"{client_id}")
        client_socket.sendall(packet.encode())
        response = client_socket.recv(1024).decode()
        if "you registered." in response:
            pass
        else:
            print("You must register first.")
            return

        # Receive the size of the message first (4 bytes)
        size_data = client_socket.recv(4)
        expected_size = int.from_bytes(size_data, 'big')

        # Get privateKDF key of recipient from server
        # Receive the message of the specified length
        chunks = []
        total_received = 0
        while total_received < expected_size:
            chunk = client_socket.recv(
                min(1024, expected_size - total_received))  # Ensure not to receive more than the expected size
            if not chunk:
                break
            chunks.append(chunk)
            total_received += len(chunk)

        privateKDF_key_pem = b''.join(chunks)
        salt_hex, iv_hex, encrypted_data_hex = privateKDF_key_pem.split(b'|')

        salt = bytes.fromhex(salt_hex.decode())
        iv = bytes.fromhex(iv_hex.decode())
        encrypted_data = bytes.fromhex(encrypted_data_hex.decode())

        password = input("Enter your password to decrypt your received data: ").encode()
        private_key_pem = Encryption.decrypt_private_key(salt, iv, encrypted_data, password)

        # Return an object of type RSAPrivateKey
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None
            )
            print("Signature is valid")
        except ValueError as e:
            if "password may be incorrect" in str(e):
                print("The password is incorrect. Please try again.")
                sys.exit()
            else:
                print(f"An error occurred: {e}")
                sys.exit()
        except Exception as e:
            print(f"Unexpected error: {e}")
            sys.exit()

        while True:
            # Receive the length of the message (4 bytes)
            length_bytes = client_socket.recv(4)
            if not length_bytes:
                return None  # Connection closed or no data
            message_length = int.from_bytes(length_bytes, 'big')

            # Receive the exact message length
            sender_id = b""
            while len(sender_id) < message_length:
                chunk = client_socket.recv(message_length - len(sender_id))
                if not chunk:
                    break  # Connection closed
                sender_id += chunk
            if "ew messages." in sender_id.decode():
                print("No new messages.")
                break

            # Receive the size of the message first (4 bytes)
            size_msg = client_socket.recv(4)
            expected_size = int.from_bytes(size_msg, 'big')
            # Exit if the messages were read
            if size_msg == b'':
                client_socket.close()
                break

            # Receive the message of the specified length
            chunks = []
            total_received = 0
            while total_received < expected_size:
                chunk = client_socket.recv(
                    min(1024, expected_size - total_received))  # Ensure not to receive more than the expected size
                if not chunk:
                    break
                chunks.append(chunk)
                total_received += len(chunk)

            msg = b''.join(chunks)

            if msg.decode() == b'':
                break

            encrypted_aes_key_hex, iv_hex, ciphertext_hex, tag_hex = msg.decode().split("|")
            # Decrypt AES key with the private key
            encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)
            aes_key = Encryption.decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

            # Decrypt message with AES key, IV, ciphertext and tag
            decrypted_message = Encryption.decrypt_message_aes(
                aes_key,
                bytes.fromhex(iv_hex),
                bytes.fromhex(ciphertext_hex),
                bytes.fromhex(tag_hex)
            ).decode()
            print(f"Message from {sender_id.decode()}: {decrypted_message}")


if __name__ == "__main__":
    print("1. Register Client")
    print("2. Send Message")
    print("3. Receive Messages")
    print("4. EXIT")

    choice = input("Enter your choice: ")
    if choice == "1":
        register_client()
    elif choice == "2":
        send_message()
    elif choice == "3":
        receive_messages()
    elif choice == "4":
        print("Disconnecting...Goodbye!")
    else:
        print("Invalid choice. Please choose again.")
