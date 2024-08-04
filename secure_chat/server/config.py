
import json

with open('../config/configuration.json', 'r') as config_file:
    config = json.load(config_file)

WEBSOCKET_PORT_RANGE_START = int(config['applicationServerDetails']['defaultServerPort'])
WEBSOCKET_PORT_RANGE_END = WEBSOCKET_PORT_RANGE_START + 100  # Assuming a range of 100 ports
FLASK_PORT = int(config['applicationServerDetails']['defaultClientPort'])
OTHER_SERVERS = ["ws://{}:{}".format(server['address'], WEBSOCKET_PORT_RANGE_START) for server in config['server']]
