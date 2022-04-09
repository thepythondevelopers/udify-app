from pydantic import BaseModel
from typing import Optional

class UserLoginModel(BaseModel):
    email: str
    password: str
