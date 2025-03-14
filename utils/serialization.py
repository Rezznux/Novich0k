import base64
import json
import logging
from datetime import datetime
from umbral import Capsule, PublicKey
from .error_types import DeserializationError, SerializationError, VersionError

logger = logging.getLogger(__name__)

def serialize_object(obj, obj_type):
    """Standardized serialization for all object types"""
    try:
        if obj_type == "capsule":
            # Use to_bytes() method for Capsule objects if available
            if hasattr(obj, 'to_bytes') and callable(getattr(obj, 'to_bytes')):
                serialized = base64.b64encode(obj.to_bytes()).decode()
            else:
                serialized = base64.b64encode(bytes(obj)).decode()
        elif obj_type == "key":
            # Use to_bytes() method for Key objects if available
            if hasattr(obj, 'to_bytes') and callable(getattr(obj, 'to_bytes')):
                serialized = base64.b64encode(obj.to_bytes()).decode()
            else:
                serialized = base64.b64encode(bytes(obj)).decode()
        elif obj_type == "message":
            serialized = json.dumps(obj)
        else:
            raise ValueError(f"Unknown object type: {obj_type}")
        return serialized
    except Exception as e:
        logger.error(f"Serialization error for {obj_type}: {e}")
        raise SerializationError(f"Could not serialize {obj_type}: {e}")

def deserialize_object(data, obj_type):
    """Standardized deserialization with validation"""
    try:
        if obj_type == "capsule":
            # Ensure we're working with bytes, not str
            if isinstance(data, str):
                decoded = base64.b64decode(data)
            else:
                decoded = base64.b64decode(data)
            return Capsule.from_bytes(decoded)
        elif obj_type == "key":
            # Ensure we're working with bytes, not str
            if isinstance(data, str):
                decoded = base64.b64decode(data)
            else:
                decoded = base64.b64decode(data)
            return PublicKey.from_bytes(decoded)
        elif obj_type == "message":
            if isinstance(data, bytes):
                return json.loads(data.decode())
            return json.loads(data)
        else:
            raise ValueError(f"Unknown object type: {obj_type}")
    except Exception as e:
        logger.error(f"Deserialization error for {obj_type}: {e}")
        raise DeserializationError(f"Could not deserialize {obj_type}: {e}")

def create_message(payload, message_type):
    """Create a message with protocol version"""
    message = {
        "protocol_version": "1.0",
        "message_type": message_type,
        "timestamp": datetime.now().isoformat(),
        "payload": payload
    }
    return message

def validate_message(message):
    """Validate incoming message schema and version"""
    required_fields = ["protocol_version", "message_type", "payload"]
    for field in required_fields:
        if field not in message:
            raise ValueError(f"Message missing required field: {field}")
    
    if message["protocol_version"] != "1.0":
        raise VersionError(f"Unsupported protocol version: {message['protocol_version']}")
    
    return True
