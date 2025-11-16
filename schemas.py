"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogs" collection
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime

class User(BaseModel):
    """
    Users collection schema
    Collection name: "user" (lowercase of class name)
    """
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    role: str = Field("student", description="Role within the exam portal: student | teacher | admin")
    is_active: bool = Field(True, description="Whether user is active")
    reset_code: Optional[str] = Field(None, description="One-time 6-digit code for password reset")
    reset_expires: Optional[datetime] = Field(None, description="Expiry timestamp for the reset code")

# You can define more collections as needed (e.g., exams, results, attempts)
