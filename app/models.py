from pydantic import BaseModel
from typing import Optional



# Pydantic Models for input validation 
class UserModel(BaseModel):
    first_name : str 
    last_name : str
    email: str 
    password: str
    access: Optional[int]
    public_id: Optional[str]
    address_state: Optional[str] = None
    address_city: Optional[str] =  None
    address_zip: Optional[str] = None
    address_country: Optional[str] = None
    address_unit: Optional[str] =  None
    address_street: Optional[str] = None
class UserLoginModel(BaseModel):
    email: str
    password: str

class UserResetPasswordModel(BaseModel):
    email: str

class UserSetPasswordModel(BaseModel):
    password: str
    confirm_password: str