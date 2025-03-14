def validate_json_schema(json_data, schema_type):
    """Validate JSON against schema"""
    schemas = {
        "command": {
            "required": ["id", "command", "timestamp"],
            "properties": {
                "id": {"type": "string"},
                "command": {"type": "string"},
                "timestamp": {"type": "string", "format": "date-time"}
            }
        },
        "response": {
            "required": ["id", "response", "timestamp", "client_id"],
            "properties": {
                "id": {"type": "string"},
                "response": {"type": "object"},
                "timestamp": {"type": "string", "format": "date-time"},
                "client_id": {"type": "string"}
            }
        }
    }
    
    if schema_type not in schemas:
        raise ValueError(f"Unknown schema type: {schema_type}")
        
    schema = schemas[schema_type]
    
    # Check required fields
    for field in schema["required"]:
        if field not in json_data:
            return False, f"Missing required field: {field}"
            
    # Check property types
    for field, props in schema["properties"].items():
        if field in json_data:
            if props["type"] == "string" and not isinstance(json_data[field], str):
                return False, f"Field {field} should be a string"
            elif props["type"] == "object" and not isinstance(json_data[field], dict):
                return False, f"Field {field} should be an object"
                
    return True, "Valid"