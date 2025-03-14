class NovichokError(Exception):
    """Base exception for all Novich0k errors"""
    pass

class DeserializationError(NovichokError):
    """Error during object deserialization"""
    pass

class SerializationError(NovichokError):
    """Error during object serialization"""
    pass

class VersionError(NovichokError):
    """Error due to protocol version mismatch"""
    pass

class CapsuleError(NovichokError):
    """Error during capsule operations"""
    pass

class CryptoError(NovichokError):
    """Error during cryptographic operations"""
    pass