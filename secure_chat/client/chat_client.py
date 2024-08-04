import asyncio
import websockets
import base64
import json
import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from pathlib import Path

def load_public_key(path):
    with open(path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

# Load public key
public_key = load_public_key(Path(__file__).parent.parent / 'keys/public_key.pem')

# RSA encryption function
def encrypt_message(message, public_key):
    try:
        ciphertext = public_key.encrypt(
            message.encode('utf8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Use SHA256
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode('utf8')
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

# Chunking function
def chunk_message(message, chunk_size=2048):
    return [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]

# Validate and sanitize input message
def validate_message(message):
    if isinstance(message, str) and len(message) <= 4096:  # Example length limit
        return message
    return None

def load_config(path='config/configuration.json'):
    with open(path, 'r') as config_file:
        return json.load(config_file)

def register(base_url, username, password):
    try:
        response = requests.post(f"{base_url}/register", json={"username": username, "password": password})
        print(f"Response status code: {response.status_code}")
        print(f"Response content: {response.text}")
        if response.status_code == 201:
            print("User registered successfully.")
        else:
            try:
                print(f"Registration failed: {response.json()['msg']}")
            except requests.exceptions.JSONDecodeError:
                print("Failed to decode JSON response")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")

def login(base_url, username, password):
    try:
        response = requests.post(f"{base_url}/login", json={"username": username, "password": password})
        print(f"Response status code: {response.status_code}")
        print(f"Response content: {response.text}")
        if response.status_code == 200:
            return response.json()['access_token']
        else:
            try:
                print(f"Login failed: {response.json()['msg']}")
            except requests.exceptions.JSONDecodeError:
                print("Failed to decode JSON response")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

async def send_message(websocket, message):
    validated_message = validate_message(message)
    if validated_message:
        encrypted_message = encrypt_message(validated_message, public_key)
        if encrypted_message:
            chunks = chunk_message(encrypted_message)
            for chunk in chunks:
                await websocket.send(chunk)
                print(f"Sent chunk: {chunk}")
            # Indicate end of message
            await websocket.send("[END]")

async def receive_message(websocket):
    while True:
        try:
            response = await websocket.recv()
            print(f"Received message: {response}")
        except websockets.ConnectionClosed:
            print("Connection closed")
            break

async def chat_client(token):
    config = load_config()
    uri = f"ws://{config['applicationServerDetails']['defaultDomainName']}:{config['applicationServerDetails']['defaultServerPort']}"
    print(f"Attempting to connect to {uri}")
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected to server.")
            await websocket.send(token)
            receive_task = asyncio.create_task(receive_message(websocket))

            while True:
                message = input("Enter your message: ")
                await send_message(websocket, message)

    except Exception as e:
        print(f"Connection error: {e}")

# Run the chat client
if __name__ == "__main__":
    config = load_config()
    base_url = f"http://{config['applicationServerDetails']['defaultDomainName']}:{config['applicationServerDetails']['defaultClientPort']}"

    print("1. Register")
    print("2. Login")
    choice = input("Choose an option: ")

    username = input("Enter username: ")
    password = input("Enter password: ")

    if choice == '1':
        register(base_url, username, password)
    elif choice == '2':
        token = login(base_url, username, password)
        if token:
            asyncio.run(chat_client(token))
