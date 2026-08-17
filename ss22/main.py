from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from dotenv import load_dotenv
import bcrypt
import jwt
import os
from datetime import datetime, timedelta, timezone

load_dotenv()

app = FastAPI(title="DevConnect Authentication API")

# SECRET KEY lấy từ file .env
SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise Exception("SECRET_KEY chưa được cấu hình trong file .env")

ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30

# Database giả lập
users_db = {}

security = HTTPBearer()


# =========================
# MODEL
# =========================

class UserRegister(BaseModel):
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


# =========================
# REGISTER
# =========================

@app.post("/api/register")
def register(user: UserRegister):

    # Kiểm tra username đã tồn tại
    if user.username in users_db:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    # Chuyển password thành bytes
    password_bytes = user.password.encode("utf-8")

    # Tạo salt + hash password
    hashed_password = bcrypt.hashpw(
        password_bytes,
        bcrypt.gensalt()
    )

    # Lưu username + hashed_password
    users_db[user.username] = {
        "username": user.username,
        "hashed_password": hashed_password
    }

    return {
        "message": "Register successfully",
        "username": user.username
    }


# =========================
# LOGIN
# =========================

@app.post("/api/login")
def login(user: UserLogin):

    # Tìm user
    db_user = users_db.get(user.username)

    # Không tìm thấy user
    if not db_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    # Kiểm tra password
    password_correct = bcrypt.checkpw(
        user.password.encode("utf-8"),
        db_user["hashed_password"]
    )

    if not password_correct:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    # Thời gian hiện tại
    now = datetime.now(timezone.utc)

    # Token hết hạn sau đúng 30 phút
    expire_time = now + timedelta(minutes=30)

    # Payload
    payload = {
        "sub": user.username,
        "iat": int(now.timestamp()),
        "exp": int(expire_time.timestamp())
    }

    # Tạo JWT
    access_token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 1800
    }


# =========================
# GET CURRENT USER
# =========================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    try:
        # Decode và kiểm tra JWT
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")

        if not username:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )

        return username

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token has expired"
        )

    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )


# =========================
# PROFILE
# =========================

@app.get("/api/profile")
def profile(username: str = Depends(get_current_user)):

    return {
        "message": f"Welcome, {username}!"
    }