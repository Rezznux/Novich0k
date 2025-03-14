class MessageBuffer:
    def __init__(self):
        self.buffer = b""
        self.expected_length = None
        
    def add_data(self, data):
        """Add received data to buffer"""
        self.buffer += data
        
        # Try to extract message length if not known
        if self.expected_length is None and len(self.buffer) >= 4:
            self.expected_length = int.from_bytes(self.buffer[:4], byteorder='big')
            
        # Check if we have a complete message
        if self.expected_length is not None and len(self.buffer) >= self.expected_length + 4:
            message = self.buffer[4:self.expected_length + 4]
            self.buffer = self.buffer[self.expected_length + 4:]
            self.expected_length = None
            return message
            
        return None
        
    def clear(self):
        """Clear the buffer"""
        self.buffer = b""
        self.expected_length = None