#!/usr/bin/env python3
"""
Umbral Capsule Serialization Diagnostic Script
----------------------------------------------
This script tests various ways to handle Umbral Capsule objects,
particularly focusing on serialization/deserialization methods
to help diagnose issues in the PRE C2 implementation.
"""

import base64
import json
import sys
import traceback
from umbral import SecretKey, PublicKey, Signer
from umbral.curve import SECP256K1
from umbral.pre import encrypt, decrypt_original, decrypt_reencrypted, reencrypt
from umbral import Capsule, CapsuleFrag

def print_separator(title):
    """Print a formatted separator with title"""
    print("\n" + "=" * 80)
    print(f" {title} ".center(80, "="))
    print("=" * 80 + "\n")

def print_type_info(obj, name):
    """Print detailed information about an object's type and methods"""
    print(f"Object: {name}")
    print(f"Type: {type(obj)}")
    print(f"Dir: {dir(obj)[:5]}... (truncated)")
    
    # Check if object is bytes-like
    try:
        memoryview(obj)
        print("✓ Object is bytes-like (memoryview works)")
    except TypeError:
        print("✗ Object is NOT bytes-like (memoryview fails)")
    
    # Check if object can be converted to bytes
    try:
        bytes_result = bytes(obj)
        print(f"✓ bytes(obj) works: {type(bytes_result)}, length={len(bytes_result)}")
    except Exception as e:
        print(f"✗ bytes(obj) fails: {e}")
    
    # Check if object has to_bytes method
    if hasattr(obj, 'to_bytes') and callable(getattr(obj, 'to_bytes')):
        try:
            result = obj.to_bytes()
            print(f"✓ obj.to_bytes() works: {type(result)}, length={len(result)}")
        except Exception as e:
            print(f"✗ obj.to_bytes() fails: {e}")
    else:
        print("✗ obj.to_bytes() method not available")
    
    print("")

def test_serialization_methods(obj, name):
    """Test different serialization methods on an object"""
    print(f"Testing serialization methods for {name}:")
    
    methods = [
        ("Direct base64", lambda x: base64.b64encode(x)),
        ("bytes() then base64", lambda x: base64.b64encode(bytes(x))),
        ("str() then encode", lambda x: str(x).encode()),
        ("repr() then encode", lambda x: repr(x).encode()),
    ]
    
    if hasattr(obj, 'to_bytes') and callable(getattr(obj, 'to_bytes')):
        methods.append(("to_bytes() then base64", lambda x: base64.b64encode(x.to_bytes())))
    
    for method_name, method in methods:
        try:
            result = method(obj)
            print(f"✓ {method_name}: {result[:20]}... (truncated)")
            
            # Try to include in a dict and convert to JSON
            try:
                json_str = json.dumps({"data": result.decode()})
                print(f"  ✓ JSON serialization works: {json_str[:30]}...")
            except Exception as e:
                print(f"  ✗ JSON serialization fails: {e}")
                
        except Exception as e:
            print(f"✗ {method_name} fails: {e}")
    
    print("")

def test_full_workflow():
    """Test a full encryption/decryption workflow"""
    print_separator("FULL WORKFLOW TEST")
    
    # Generate keys
    private_key_a = SecretKey.random()
    public_key_a = private_key_a.public_key()
    
    private_key_b = SecretKey.random()
    public_key_b = private_key_b.public_key()
    
    # Create a message
    message = b"This is a test message for Umbral PRE encryption."
    
    # Encrypt with public key A
    print("Encrypting message...")
    ciphertext, capsule = encrypt(public_key_a, message)
    
    print("Original capsule type information:")
    print_type_info(capsule, "capsule")
    
    # Test serialization methods
    test_serialization_methods(capsule, "capsule")
    
    # Serialize the capsule with different methods
    try:
        # Method 1: Direct bytes
        capsule_bytes_direct = capsule
        
        # Method 2: Using bytes()
        capsule_bytes_conversion = bytes(capsule)
        
        # Method 3: Using to_bytes() if available
        if hasattr(capsule, 'to_bytes'):
            capsule_bytes_to_bytes = capsule.to_bytes()
        else:
            capsule_bytes_to_bytes = None
        
        # Base64 encode each method
        capsule_b64_direct = base64.b64encode(capsule_bytes_direct).decode()
        capsule_b64_conversion = base64.b64encode(capsule_bytes_conversion).decode()
        capsule_b64_to_bytes = base64.b64encode(capsule_bytes_to_bytes).decode() if capsule_bytes_to_bytes is not None else None
        
        print("Serialization results:")
        print(f"Method 1 (direct): {capsule_b64_direct[:30]}...")
        print(f"Method 2 (bytes()): {capsule_b64_conversion[:30]}...")
        if capsule_b64_to_bytes:
            print(f"Method 3 (to_bytes()): {capsule_b64_to_bytes[:30]}...")
        
        # Check if methods produce the same result
        if capsule_b64_direct == capsule_b64_conversion:
            print("✓ Direct and bytes() methods produce identical results")
        else:
            print("✗ Direct and bytes() methods produce different results")
        
        if capsule_b64_to_bytes:
            if capsule_b64_direct == capsule_b64_to_bytes:
                print("✓ Direct and to_bytes() methods produce identical results")
            else:
                print("✗ Direct and to_bytes() methods produce different results")
            
            if capsule_b64_conversion == capsule_b64_to_bytes:
                print("✓ bytes() and to_bytes() methods produce identical results")
            else:
                print("✗ bytes() and to_bytes() methods produce different results")
        
        # Test deserialization
        print("\nDeserialization test:")
        
        # Method 1: From direct bytes
        try:
            capsule_from_direct = Capsule.from_bytes(base64.b64decode(capsule_b64_direct))
            print("✓ Deserialization of direct method works")
        except Exception as e:
            print(f"✗ Deserialization of direct method fails: {e}")
        
        # Method 2: From bytes() conversion
        try:
            capsule_from_conversion = Capsule.from_bytes(base64.b64decode(capsule_b64_conversion))
            print("✓ Deserialization of bytes() method works")
        except Exception as e:
            print(f"✗ Deserialization of bytes() method fails: {e}")
        
        # Method 3: From to_bytes() method
        if capsule_b64_to_bytes:
            try:
                capsule_from_to_bytes = Capsule.from_bytes(base64.b64decode(capsule_b64_to_bytes))
                print("✓ Deserialization of to_bytes() method works")
            except Exception as e:
                print(f"✗ Deserialization of to_bytes() method fails: {e}")
        
        # Test message recreation
        print("\nDecryption test:")
        
        # Using original capsule
        try:
            decrypted_original = decrypt_original(
                delegating_sk=private_key_a,
                capsule=capsule,
                ciphertext=ciphertext
            )
            print(f"✓ Original decryption works: {decrypted_original}")
        except Exception as e:
            print(f"✗ Original decryption fails: {e}")
        
        # Using deserialized capsule
        try:
            decrypted_from_direct = decrypt_original(
                delegating_sk=private_key_a,
                capsule=capsule_from_direct,
                ciphertext=ciphertext
            )
            print(f"✓ Decryption with deserialized capsule (direct method) works")
        except Exception as e:
            print(f"✗ Decryption with deserialized capsule (direct method) fails: {e}")
        
    except Exception as e:
        print(f"Error in serialization test: {e}")
        traceback.print_exc()

def test_json_serialization():
    """Test including serialized capsule in JSON"""
    print_separator("JSON SERIALIZATION TEST")
    
    # Generate keys
    private_key = SecretKey.random()
    public_key = private_key.public_key()
    
    # Create a message
    message = b"Testing JSON serialization of Umbral objects"
    
    # Encrypt
    ciphertext, capsule = encrypt(public_key, message)
    
    # Try different serialization approaches for a full message
    serialization_methods = [
        ("Direct capsule", lambda c: base64.b64encode(c).decode()),
        ("bytes(capsule)", lambda c: base64.b64encode(bytes(c)).decode()),
    ]
    
    if hasattr(capsule, 'to_bytes'):
        serialization_methods.append(("capsule.to_bytes()", lambda c: base64.b64encode(c.to_bytes()).decode()))
    
    for method_name, serialize_func in serialization_methods:
        try:
            # Create a command dict similar to the one in the C2 code
            command = {
                'command': True,
                'encrypted_data': {
                    'ciphertext': base64.b64encode(ciphertext).decode(),
                    'capsule': serialize_func(capsule)
                }
            }
            
            # Attempt to convert to JSON
            json_str = json.dumps(command)
            print(f"✓ {method_name} JSON serialization successful: {json_str[:50]}...")
            
            # Attempt to decode back
            decoded = json.loads(json_str)
            print(f"✓ {method_name} JSON deserialization successful")
            
            # Verify structure
            if 'encrypted_data' in decoded and 'capsule' in decoded['encrypted_data']:
                print(f"✓ {method_name} structure preserved correctly")
            else:
                print(f"✗ {method_name} structure changed during serialization")
            
        except Exception as e:
            print(f"✗ {method_name} JSON serialization failed: {e}")
            traceback.print_exc()

def test_message_with_retry():
    """Simulate the send_message_with_retry function behavior"""
    print_separator("MESSAGE WITH RETRY TEST")
    
    # Generate keys
    private_key = SecretKey.random()
    public_key = private_key.public_key()
    
    # Create a message
    message_text = b"Testing message sending simulation"
    
    # Encrypt
    ciphertext, capsule = encrypt(public_key, message_text)
    
    # Approaches to try
    approaches = [
        ("Direct capsule", lambda c: c),
        ("bytes(capsule)", lambda c: bytes(c)),
    ]
    
    if hasattr(capsule, 'to_bytes'):
        approaches.append(("capsule.to_bytes()", lambda c: c.to_bytes()))
    
    for approach_name, capsule_func in approaches:
        print(f"\nTesting {approach_name}:")
        
        try:
            # Create message similar to the one in server code
            message = {
                'command': True,
                'encrypted_data': {
                    'ciphertext': base64.b64encode(ciphertext).decode(),
                    'capsule': base64.b64encode(capsule_func(capsule)).decode()
                }
            }
            
            # Simulate send_message_with_retry
            print("  Simulating dict to JSON conversion...")
            message_str = json.dumps(message)
            print(f"  ✓ JSON conversion successful: {message_str[:50]}...")
            
            print("  Simulating JSON to bytes conversion...")
            message_bytes = message_str.encode('utf-8')
            print(f"  ✓ Bytes conversion successful: {len(message_bytes)} bytes")
            
            print("  Simulating length prefix addition...")
            length_prefix = len(message_bytes).to_bytes(4, byteorder='big')
            full_message = length_prefix + message_bytes
            print(f"  ✓ Full message prepared: {len(full_message)} total bytes")
            
            print(f"✓ {approach_name} passed full simulation")
            
        except Exception as e:
            print(f"✗ {approach_name} failed: {e}")
            traceback.print_exc()

def main():
    print_separator("UMBRAL CAPSULE SERIALIZATION DIAGNOSTIC")
    print(f"Python version: {sys.version}")
    print(f"Umbral version: {getattr(Capsule, '__module__', 'Unknown')}")
    
    try:
        # Test basic Capsule creation and properties
        print_separator("BASIC CAPSULE PROPERTIES")
        
        # Generate keys
        private_key = SecretKey.random()
        public_key = private_key.public_key()
        
        # Create a simple message and encrypt it
        message = b"Hello, Umbral!"
        ciphertext, capsule = encrypt(public_key, message)
        
        # Examine the capsule
        print_type_info(capsule, "Capsule from encrypt()")
        
        # Test serialization methods
        test_serialization_methods(capsule, "Capsule")
        
        # Test full workflow
        test_full_workflow()
        
        # Test JSON serialization
        test_json_serialization()
        
        # Test message sending simulation
        test_message_with_retry()
        
        print_separator("RECOMMENDATION")
        print("Based on the tests above, here's the recommended approach for handling Capsules:")
        print("")
        print("1. When serializing a Capsule for inclusion in a JSON message:")
        
        if hasattr(Capsule, 'to_bytes'):
            print("   capsule_bytes = capsule.to_bytes()")
            print("   capsule_b64 = base64.b64encode(capsule_bytes).decode()")
        else:
            print("   capsule_bytes = bytes(capsule)")
            print("   capsule_b64 = base64.b64encode(capsule_bytes).decode()")
        
        print("")
        print("2. When deserializing a Capsule from a JSON message:")
        print("   capsule_bytes = base64.b64decode(capsule_b64)")
        print("   capsule = Capsule.from_bytes(capsule_bytes)")
        
        print("")
        print("3. For your specific server_PRE_C2.py issue, modify the send_command_to_client function:")
        print("   - In both proxy and non-proxy paths, use the serialization approach above")
        print("   - Make sure the capsule is properly converted to bytes before base64 encoding")
        
    except Exception as e:
        print(f"Error in diagnostic script: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    main()
