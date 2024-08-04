# Secure-Chat-System

## Setup

### Prerequisites

- Python 3.6 or higher
- pip (Python package installer)
- openssl (for generating RSA keys)
- SQLite (for the user database)

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/Arjun278/Secure-Chat-System
    cd secure_chat
    ```

2. Create a virtual environment (optional but recommended):

    ```bash
    python3 -m venv secure_env
    source secure_env/bin/activate  # On Windows use `secure_env\Scripts\activate`
    ```

3. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

4. Generate RSA keys:

    ```bash
    mkdir -p keys
    openssl genrsa -out keys/private_key.pem 2048
    openssl rsa -in keys/private_key.pem -pubout -out keys/public_key.pem
    ```

5. Create the configuration file:

    Navigate to the `config` directory and create a file named `configuration.json` with the following content:

    ```json
    {
        "server": [
            {
                "domain": "s11",
                "address": "10.13.101.178"
            },
            {
                "domain": "s3",
                "address": "10.13.83.163"
            },
            {
                "domain": "s4",
                "address": "10.13.101.145"
            },
            {
                "domain": "s6",
                "address": "10.13.81.121"
            },
            {
                "domain": "s2",
                "address": "10.13.89.245"
            }
        ],
        "applicationServerDetails": {
            "defaultServerPort": "5555",
            "defaultClientPort": "4567",
            "defaultDomainName": "127.0.0.1"  // Ensure this is the correct IP of your server
        }
    }
    ```

## Running the Code

1. **Start the Flask server**:

    ```bash
    cd secure_chat/server
    python3 flask_app.py
    ```

2. **Start the WebSocket server**:

    ```bash
    python3 websocket_server.py
    ```

3. **Run the client script**:

    ```bash
    cd secure_chat/client
    python3 chat_client.py
    ```

### Using the Chat System

1. **Register a New User**:
    - When prompted, choose the option to register.
    - Enter a username and password.

2. **Login as an Existing User**:
    - When prompted, choose the option to login.
    - Enter your username and password.

3. **Send Messages**:
    - After logging in, you can enter your message and press Enter.
    - Your message will be encrypted, chunked, and sent to the server.
    - The server will receive, decrypt, and reassemble the message, then send it to other connected clients.
    - The client will display messages received from the server.

