#!/usr/bin/env python3
"""
Debug script to diagnose Umbral Capsule serialization issues
"""

import base64
import json
from umbral import SecretKey, PublicKey
from umbral.pre import encrypt
import sys

def debug_capsule_serialization():
    print("Umbral Capsule Serialization Debug")
    print("---------------------------------")
    
    # Generate test keys
    private_key = SecretKey.random()
    public_key = private_key.public_key()
    
    # Create a test message
    message = b"Test message for encryption"
    
    # Encrypt message
    print("Encrypting message...")
    ciphertext, capsule = encrypt(public_key, message)
    
    print(f"Capsule type: {type(capsule)}")
    print(f"Capsule class: {capsule.__class__.__name__}")
    print(f"Capsule module: {capsule.__class__.__module__}")
    
    # Try different serialization methods
    print("\nTrying different serialization methods:")
    
    # Method 1: Direct bytes conversion
    try:
        direct_bytes = bytes(capsule)
        print(f"1. bytes(capsule): Success - {type(direct_bytes)}, Length: {len(direct_bytes)}")
        print(f"   First few bytes: {direct_bytes[:10]}")
        
        # Try base64 encoding
        b64_direct = base64.b64encode(direct_bytes).decode()
        print(f"   Base64 encoded: {b64_direct[:20]}...")
    except Exception as e:
        print(f"1. bytes(capsule): Failed - {e}")
    
    # Method 2: to_bytes() method if available
    if hasattr(capsule, 'to_bytes') and callable(getattr(capsule, 'to_bytes')):
        try:
            to_bytes_result = capsule.to_bytes()
            print(f"2. capsule.to_bytes(): Success - {type(to_bytes_result)}, Length: {len(to_bytes_result)}")
            print(f"   First few bytes: {to_bytes_result[:10]}")
            
            # Try base64 encoding
            b64_to_bytes = base64.b64encode(to_bytes_result).decode()
            print(f"   Base64 encoded: {b64_to_bytes[:20]}...")
        except Exception as e:
            print(f"2. capsule.to_bytes(): Failed - {e}")
    else:
        print("2. capsule.to_bytes(): Method not available")
    
    # Method 3: Using repr
    try:
        repr_bytes = repr(capsule).encode()
        print(f"3. repr(capsule).encode(): Success - {type(repr_bytes)}, Length: {len(repr_bytes)}")
        print(f"   Result: {repr_bytes[:30]}...")
        
        # Try base64 encoding
        b64_repr = base64.b64encode(repr_bytes).decode()
        print(f"   Base64 encoded: {b64_repr[:20]}...")
    except Exception as e:
        print(f"3. repr(capsule).encode(): Failed - {e}")
    
    # Method 4: Using str
    try:
        str_bytes = str(capsule).encode()
        print(f"4. str(capsule).encode(): Success - {type(str_bytes)}, Length: {len(str_bytes)}")
        print(f"   Result: {str_bytes[:30]}...")
        
        # Try base64 encoding
        b64_str = base64.b64encode(str_bytes).decode()
        print(f"   Base64 encoded: {b64_str[:20]}...")
    except Exception as e:
        print(f"4. str(capsule).encode(): Failed - {e}")
    
    # Print capsule attributes
    print("\nCapsule attributes and methods:")
    for attr in dir(capsule):
        if not attr.startswith('__'):
            attr_type = "method" if callable(getattr(capsule, attr)) else "attribute"
            print(f"- {attr} ({attr_type})")
    
    # Print memory address to check if bytes() is returning a reference
    print(f"\nCapsule memory address: {hex(id(capsule))}")
    try:
        bytes_mem_address = hex(id(bytes(capsule)))
        print(f"bytes(capsule) memory address: {bytes_mem_address}")
        print(f"Is same object: {id(capsule) == id(bytes(capsule))}")
    except Exception as e:
        print(f"Could not get bytes(capsule) memory address: {e}")
    
    print("\nRecommendation for your code:")
    print("-----------------------------")
    print("Based on the above tests, here's what you should try in your code:")
    print("""
try:
    # First method: Try direct bytes conversion
    capsule_bytes = bytes(capsule)
    
    # Verify we got actual bytes and not just a reference
    if not isinstance(capsule_bytes, bytes):
        # Second method: If capsule has to_bytes method, use it
        if hasattr(capsule, 'to_bytes') and callable(getattr(capsule, 'to_bytes')):
            capsule_bytes = capsule.to_bytes()
        else:
            # Third method: Try using byte representation
            capsule_bytes = repr(capsule).encode()
    
    # Now use capsule_bytes for base64 encoding
    b64_capsule = base64.b64encode(capsule_bytes).decode()
except Exception as e:
    print(f"Error converting capsule to bytes: {e}")
    # Handle the error appropriately
""")

if __name__ == "__main__":
    debug_capsule_serialization()
