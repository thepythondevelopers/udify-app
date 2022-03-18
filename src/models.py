from pydantic import BaseModel
from typing import Optional



# Pydantic Models for input validation 
class UserModel(BaseModel):
    first_name : str 
    last_name : str
    email: str 
    password: str
    access: Optional[int]

class UserLoginModel(BaseModel):
    email: str
    password: str

class UserResetPasswordModel(BaseModel):
    email: str

class UserSetPasswordModel(BaseModel):
    password: str
    confirm_password: str