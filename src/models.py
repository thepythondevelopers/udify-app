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
    address_state: Optional[str]
    address_city: Optional[str]
    address_zip: Optional[str]
    address_country: Optional[str]
    address_unit: Optional[str]
    address_street: Optional[str]
class UserLoginModel(BaseModel):
    email: str
    password: str

class UserResetPasswordModel(BaseModel):
    email: str

class UserSetPasswordModel(BaseModel):
    password: str
    confirm_password: str