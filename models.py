# models.py
from pydantic import BaseModel, EmailStr, Field
from uuid import UUID
from typing import Optional


class User(BaseModel):
    id: str
    email: EmailStr
    username: str
    first_name: str
    last_name: str
    phone_number: str

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    username: str
    first_name: str
    last_name: str
    phone_number: str
    
class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone_number: Optional[str] = None
    
class EmailVerificationRequest(BaseModel):
    email: EmailStr

# Define the TokenData model
class TokenData(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    token_type: Optional[str] = "Bearer"
    expires_in: Optional[int] = None

class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = Field(None, description="Refresh token to be revoked")