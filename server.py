import socket
import threading
from cryptography.hazmat.primitives import serialization
from database import ServerDatabase
from encryption import Encryption

HOST = '127.0.0.1'
PORT = 65432

db = ServerDatabase()

def handle_client(conn, addr):
    try:
        # Client choice
        choice = conn.recv(1024).decode()
        conn.sendall(b"Choice approved")
        if choice == "1":
            # Receive client registration details
            data = conn.recv(1024).decode()
            client_id, public_key_pem = data.split("|", 1)
            # Separate the Client phone number from the PacketType and deleting a secret prefix
            packet_parts = client_id.split(":")
            client_id = packet_parts[1]

            # Check if the client is already registered
            if db.is_client_registered(client_id):
                conn.sendall(b"Client already registered.")
                print(f"Client {client_id} already registered.")
                return
            else:
                conn.sendall(b"New Client.")

            # Return an object of type RSAPublicKey
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            # Generate and send verification code to client
            verification_code = Encryption.generate_verification_code()  # 6 digit code
            print(f"Generated verification code: {verification_code}")  # Debug
            conn.sendall(verification_code.encode())
            print("Verification code sent.")

            # Wait for verification code from the client
            print("Wait for signature from the client")
            signature = conn.recv(1024)

            # Verify the signature
            if Encryption.verify_signature(public_key, verification_code, signature):
                # Server store the client in db of the server
                print(f"Client {client_id} verified and registered.")
                conn.sendall(b"Verification approved")
                privateKDF_key_pem = b""
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    privateKDF_key_pem += data

                db.register_client(client_id, public_key_pem, privateKDF_key_pem)
            else:
                conn.sendall(b"Invalid signature, Registration failed.")
                return  # Close connection if invalid signature

        elif choice == "2":  # Send Message
            client_id = conn.recv(1024).decode()
            # Deleting a secret prefix
            packet_parts = client_id.split(":")
            client_id = packet_parts[1]
            # Server check if the sender is in db
            if not db.is_client_registered(client_id):
                print("Someone tried to send message without registration")
                conn.sendall(b"you must register first.")
                return
            else:
                conn.sendall(b"you registered.")

            recipient_id = conn.recv(1024).decode()
            # Server check if the recipient is in db
            if not db.is_client_registered(recipient_id):
                print(f"Client {client_id} sending message to {recipient_id}")
                conn.sendall(b"Recipient not found. Returning to menu.")
                return

            # Server send the recipient public key
            conn.sendall(b"Recipient found")
            public_key = db.get_client_public_key(recipient_id)
            conn.sendall(public_key.encode())  # Send the public key to the client
            print("recipient public key sent successfully to sender for encrypt the message")

            # Server receive the sender encrypted message and store it in db of the server
            message = conn.recv(1024).decode()
            db.store_message(recipient_id, client_id, message)
            print("Message stored successfully.")
            conn.sendall(b"Message sent successfully.")

        elif choice == "3":  # Receive Messages
            packet = conn.recv(1024).decode()
            # Deleting a secret prefix
            packet_parts = packet.split(":")
            recipient_id = packet_parts[1]
            # Server check if the recipient is in db
            if not db.is_client_registered(recipient_id):
                print("Someone tried to read messages without registration")
                conn.sendall(b"you must register first to receive messages.")
                return
            else:
                conn.sendall(b"you registered.")

            privateKDF_key_pem = db.get_client_private_key(recipient_id)
            key_length = len(privateKDF_key_pem)
            # Send the public key to the client
            conn.sendall(key_length.to_bytes(4, 'big'))  # Send the size of the message (4 bytes)
            conn.sendall(privateKDF_key_pem)  # Send the actual message
            print("recipient private key sent successfully for decrypt the message")
            # Get all messages of the client
            messages = db.pending_messages.get(recipient_id, [])

            # Server send senders id and messages to client one by one (if not empty)
            if messages:
                for msg in messages:
                    sender_id = msg['sender_id']
                    sender_id_length = len(sender_id)
                    conn.sendall(sender_id_length.to_bytes(4, 'big'))  # Send the size of the message (4 bytes)
                    conn.sendall(sender_id.encode())
                    message = msg['message']
                    message_length = len(message)
                    conn.sendall(message_length.to_bytes(4, 'big'))  # Send the size of the message (4 bytes)
                    conn.sendall(message.encode())
                print(f"Client {recipient_id} received his messages")
            else:
                conn.sendall(b"No new messages.")

            db.pending_messages[recipient_id].clear()

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
        print(f"Client disconnected: {addr}")


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()


if __name__ == "__main__":
    start_server()
