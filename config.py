import os
from dotenv import load_dotenv

load_dotenv()

class Config:

    DB_HOST = os.getenv("DB_HOST")
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    DB_NAME = os.getenv("DB_NAME")

    SECRET_KEY = os.getenv("FLASK_SECRET_KEY")

    # 🔐 FERNET
    fernet_key = os.getenv("FERNET_KEY")
    FERNET_KEY = fernet_key.encode() if fernet_key else None

    # 🚀 APP CONFIG
    APP_HOST = os.getenv("APP_HOST", "127.0.0.1")
    APP_PORT = int(os.getenv("APP_PORT", 5000))
    APP_DEBUG = os.getenv("APP_DEBUG", "false").lower() == "true"
