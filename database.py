class ServerDatabase:

    def __init__(self):
        self.clients = {}
        self.pending_messages = {}

    # The keys saved as a PEM format
    def register_client(self, client_id, public_key, private_key):
        self.clients[client_id] = {
            'public_key': public_key,
            'private_key': private_key
        }

    def is_client_registered(self, client_id):
        """Check if the client is registered"""
        return client_id in self.clients

    def get_client_public_key(self, client_id):
        """Get the public key of a specific client by their ID."""
        if client_id in self.clients:
            return self.clients[client_id].get("public_key")
        return None  # Client not found

    def get_client_private_key(self, client_id):
        """Get the private key of a specific client by their ID."""
        if client_id in self.clients:
            return self.clients[client_id].get("private_key")
        return None  # Private key not found

    def store_message(self, recipient_id, sender_id, message):
        if recipient_id not in self.pending_messages:
            self.pending_messages[recipient_id] = []
        if len(self.pending_messages[recipient_id]) < 2:
            self.pending_messages[recipient_id].append({'sender_id': sender_id, 'message': message})

    def get_messages(self, recipient_id):
        return [item['message'] for item in self.pending_messages.pop(recipient_id, [])]

    def get_sender_ids(self, recipient_id):
        return [item['sender_id'] for item in self.pending_messages.get(recipient_id, [])]

    # def get_messages(self, recipient_id):
    #   return self.pending_messages.pop(recipient_id, [])
