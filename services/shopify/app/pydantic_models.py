from pydantic import BaseModel
from typing import Optional

# Pydantic Models for input validation 
class IntegrationModel(BaseModel):
    store_api_key : str 
    store_api_secret : str
    domain: str 