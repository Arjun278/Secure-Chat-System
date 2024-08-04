import asyncio
import socket
import websockets
import nest_asyncio
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from keys import load_private_key
from jwt import decode, InvalidTokenError
import json
import os

nest_asyncio.apply()

# Load private key
private_key = load_private_key()

# Helper function to find an available port
def find_available_port():
    for port in range(5555, 5655):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('0.0.0.0', port))
        if result != 0:
            return port
        sock.close()

# RSA decryption function
def decrypt_message(ciphertext, private_key):
    try:
        ciphertext = base64.b64decode(ciphertext)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# Validate and sanitize input message
def validate_message(message):
    if isinstance(message, str) and len(message) <= 4096:
        return message
    return None

connected_clients = set()
active_users = {}

async def handler(websocket, path):
    token = await websocket.recv()
    try:
        user_data = decode(token, os.getenv('JWT_SECRET_KEY', 'default_jwt_secret_key'), algorithms=["HS256"])
        username = user_data['sub']
        active_users[websocket] = username
        print(f"User {username} connected")
    except InvalidTokenError as e:
        print(f"Invalid token: {e}")
        await websocket.close()
        return

    connected_clients.add(websocket)
    try:
        message_parts = []
        while True:
            chunk = await websocket.recv()
            if chunk == "[END]":
                encrypted_message = ''.join(message_parts)
                decrypted_message = decrypt_message(encrypted_message, private_key)
                validated_message = validate_message(decrypted_message)
                if validated_message:
                    print(f"Received message from {active_users[websocket]}: {validated_message}")
                    await asyncio.gather(*[client.send(f"{active_users[websocket]}: {validated_message}") for client in connected_clients if client != websocket])
                message_parts = []
            else:
                message_parts.append(chunk)
    except websockets.ConnectionClosed:
        print("Connection closed")
    except Exception as e:
        print(f"Handler error: {e}")
    finally:
        connected_clients.remove(websocket)
        del active_users[websocket]

def start_websocket_server():
    port = find_available_port()
    start_server = websockets.serve(handler, '0.0.0.0', port)
    asyncio.get_event_loop().run_until_complete(start_server)
    print(f"WebSocket server started on ws://0.0.0.0:{port}")
    asyncio.get_event_loop().run_forever()

if __name__ == "__main__":
    start_websocket_server()
