import os
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from passlib.context import CryptContext
from database import db, create_document

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# -------------------- Root & Health --------------------
@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}

@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}

@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

# -------------------- Auth Schemas --------------------
class SignupRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str = Field(..., min_length=6, max_length=6)
    new_password: str = Field(..., min_length=6, max_length=128)

class AuthResponse(BaseModel):
    message: str
    token: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None

# -------------------- Auth Helpers --------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

# -------------------- Auth Endpoints --------------------
@app.post("/auth/signup", response_model=AuthResponse)
def signup(payload: SignupRequest):
    users = db["user"]
    existing = users.find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": hash_password(payload.password),
        "role": "student",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    users.insert_one(doc)
    return AuthResponse(message="Signup successful", name=payload.name, email=payload.email)

@app.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    users = db["user"]
    user = users.find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Simple pseudo token for demo (not a real JWT)
    token = f"token_{user['_id']}"
    return AuthResponse(message="Login successful", token=token, name=user.get("name"), email=user.get("email"))

@app.post("/auth/forgot", response_model=AuthResponse)
def forgot_password(payload: ForgotPasswordRequest):
    users = db["user"]
    user = users.find_one({"email": payload.email})
    if not user:
        # Do not reveal existence; respond success generically
        return AuthResponse(message="If the email exists, a reset code has been generated.")

    import random
    code = f"{random.randint(0, 999999):06d}"
    expires = datetime.now(timezone.utc) + timedelta(minutes=15)
    users.update_one({"_id": user["_id"]}, {"$set": {"reset_code": code, "reset_expires": expires}})
    # In a real app, send code via email. Here we return it for demo/testing.
    return AuthResponse(message="Reset code generated (demo)", token=code)

@app.post("/auth/reset", response_model=AuthResponse)
def reset_password(payload: ResetPasswordRequest):
    users = db["user"]
    user = users.find_one({"email": payload.email})
    if not user or user.get("reset_code") != payload.code:
        raise HTTPException(status_code=400, detail="Invalid code or email")

    expires: Optional[datetime] = user.get("reset_expires")
    if not expires or datetime.now(timezone.utc) > expires:
        raise HTTPException(status_code=400, detail="Reset code expired")

    users.update_one(
        {"_id": user["_id"]},
        {"$set": {"password_hash": hash_password(payload.new_password), "updated_at": datetime.now(timezone.utc)},
         "$unset": {"reset_code": "", "reset_expires": ""}}
    )
    return AuthResponse(message="Password reset successful")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
