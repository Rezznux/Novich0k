import json
import time
import socket
import logging

logger = logging.getLogger(__name__)

def send_message_with_retry(sock, message, max_retries=3, retry_delay=1.0):
    """Send a message with retry capability"""
    retries = 0
    
    while retries < max_retries:
        try:
            # Convert dict to JSON string if needed
            if isinstance(message, dict):
                message_str = json.dumps(message)
            else:
                message_str = message
                
            # Encode to bytes if it's a string
            if isinstance(message_str, str):
                message_bytes = message_str.encode('utf-8')
            else:
                message_bytes = message_str
                
            # Prefix with length
            length_prefix = len(message_bytes).to_bytes(4, byteorder='big')
            
            # Send the message
            sock.sendall(length_prefix + message_bytes)
            return True
        except (socket.error, ConnectionError) as e:
            retries += 1
            if retries >= max_retries:
                logger.error(f"Failed to send message after {max_retries} attempts: {e}")
                raise
            
            logger.warning(f"Error sending message (attempt {retries}): {e}")
            time.sleep(retry_delay)
    
    return False

def receive_message_with_timeout(sock, buffer=None, timeout=10.0):
    """Receive a message with timeout"""
    original_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    
    try:
        if buffer:
            # If we have a buffer object, use its add_data method
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        # Connection closed
                        return None
                        
                    complete_message = buffer.add_data(data)
                    if complete_message:
                        return json.loads(complete_message.decode('utf-8'))
                except socket.timeout:
                    # Return None on timeout
                    return None
        else:
            # Simple receive without buffer handling
            # Read length prefix
            length_bytes = sock.recv(4)
            if not length_bytes or len(length_bytes) < 4:
                return None
                
            message_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Read message
            message_bytes = b''
            while len(message_bytes) < message_length:
                chunk = sock.recv(min(4096, message_length - len(message_bytes)))
                if not chunk:
                    return None
                message_bytes += chunk
                
            return json.loads(message_bytes.decode('utf-8'))
    
    finally:
        # Restore original timeout
        sock.settimeout(original_timeout)
