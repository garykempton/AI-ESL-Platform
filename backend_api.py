from fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Dict, Generator
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
import psycopg2
from psycopg2.pool import SimpleConnectionPool
import os
from dotenv import load_dotenv
import logging
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import redis
import smtplib
from email.mime.text import MIMEText
import secrets

# Load environment variables
load_dotenv()

# Validate environment variables
required_env_vars = ["SECRET_KEY", "REFRESH_SECRET_KEY", "DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST", "SMTP_SERVER", "SMTP_USERNAME", "SMTP_PASSWORD", "REDIS_HOST", "REDIS_PORT"]
for var in required_env_vars:
    if not os.getenv(var):
        raise ValueError(f"Missing required environment variable: {var}")

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Redis Key Names
REDIS_REFRESH_KEY = "refresh:{}"
REDIS_VERIFY_KEY = "verify:{}"
REDIS_RATE_LIMIT_KEY = "ratelimit:{}"

# Initialize Redis with authentication and retry logic
def get_redis_connection():
    retries = 3
    for attempt in range(retries):
        try:
            return redis.Redis(
                host=os.getenv("REDIS_HOST", "localhost"),
                port=int(os.getenv("REDIS_PORT", 6379)),
                password=os.getenv("REDIS_PASSWORD"),
                db=0,
                decode_responses=True,
                ssl=True  # Ensure secure connection
            )
        except Exception as e:
            logger.error(f"Redis connection attempt {attempt+1} failed: {e}")
            if attempt == retries - 1:
                return None

redis_client = get_redis_connection()

# Token Rotation for Refresh Tokens
def rotate_refresh_token(old_token: str):
    new_token = secrets.token_urlsafe(32)
    redis_client.setex(REDIS_REFRESH_KEY.format(new_token), REFRESH_TOKEN_EXPIRE_DAYS * 86400, "valid")
    redis_client.delete(REDIS_REFRESH_KEY.format(old_token))
    return new_token

# Secure Email Verification Token Storage
def generate_verification_token():
    return secrets.token_urlsafe(32)

def store_email_verification_token(email: str, token: str):
    if redis_client:
        redis_client.setex(REDIS_VERIFY_KEY.format(token), 86400, email)

def get_email_verification_token(token: str):
    if redis_client:
        return redis_client.get(REDIS_VERIFY_KEY.format(token))
    return None

# Background Task for Email Sending
def send_email_background(background_tasks: BackgroundTasks, email: str, subject: str, body: str):
    background_tasks.add_task(send_email, email, subject, body)

def send_email(email: str, subject: str, body: str):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USERNAME
    msg["To"] = email
    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_USERNAME, email, msg.as_string())
        logger.info(f"Email sent to {email}")
    except smtplib.SMTPException as e:
        logger.error(f"Failed to send email: {e}")

# Password Reset Functionality
@app.post("/forgot-password")
def forgot_password(email: EmailStr, background_tasks: BackgroundTasks):
    reset_token = generate_verification_token()
    store_email_verification_token(email, reset_token)
    send_email_background(background_tasks, email, "Password Reset", f"Click here to reset your password: https://yourdomain.com/reset-password?token={reset_token}")
    return {"message": "Password reset email sent."}

@app.post("/reset-password")
def reset_password(token: str, new_password: str, conn=Depends(get_db_pool)):
    email = get_email_verification_token(token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid or expired token.")
    hashed_password = pwd_context.hash(new_password)
    with conn.cursor() as cursor:
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
        conn.commit()
    redis_client.delete(REDIS_VERIFY_KEY.format(token))
    return {"message": "Password reset successful."}

# Implement Token Revocation
@app.post("/revoke-token")
def revoke_token(token: str):
    redis_client.setex(REDIS_REFRESH_KEY.format(token), 0, "revoked")
    return {"message": "Token revoked successfully."}

# Implement Rate Limiting
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    user_ip = request.client.host
    if redis_client:
        request_count = redis_client.get(REDIS_RATE_LIMIT_KEY.format(user_ip))
        if request_count and int(request_count) > 100:
            raise HTTPException(status_code=429, detail="Too many requests. Try again later.")
        redis_client.incr(REDIS_RATE_LIMIT_KEY.format(user_ip))
        redis_client.expire(REDIS_RATE_LIMIT_KEY.format(user_ip), 60)
    return await call_next(request)

# Run the API
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
