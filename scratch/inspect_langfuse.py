import os
from langfuse.api import LangfuseAPI

api = LangfuseAPI(
    username="dummy",
    password="dummy",
    base_url="http://localhost:3001",
)

try:
    ret_type = api.trace.list.__annotations__.get('return')
    print("Return type is:", ret_type)
    if ret_type:
        meta_field = ret_type.model_fields.get('meta')
        print("meta_field:", meta_field)
        meta_type = meta_field.annotation
        print("meta_type is:", meta_type)
        if hasattr(meta_type, "model_fields"):
            print("Meta fields:", meta_type.model_fields.keys())
        elif hasattr(meta_type, "__fields__"):
            print("Meta fields dict:", meta_type.__fields__.keys())
        else:
            print("Attributes of meta_type:", dir(meta_type))
except Exception as e:
    print(f"Error: {e}")

