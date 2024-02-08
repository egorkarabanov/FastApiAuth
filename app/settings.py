from os import environ
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ALLOWED_HOST: str = environ.get("ALLOWED_HOST")
    DEBUG: bool = bool(environ.get("DEBUG"))
    ALLOWED_PORT: int = int(environ.get("PORT"))

    DB_USER: str = environ.get("POSTGRES_USER")
    DB_PASSWORD: str = environ.get("POSTGRES_PASSWORD")
    DB_NAME: str = environ.get("POSTGRES_DB")
    DB_PORT: str = environ.get("POSTGRES_PORT")
    DB_HOST: str = environ.get("POSTGRES_HOST")
    DB_URL: str = f"postgresql+asyncpg://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    DB_DEBUG: bool = True if DEBUG else False

    SECRET_KEY: str = environ.get("SECRET_KEY", "5bd7e468d62ae51c0d85e92019e29dcb98c50092ee97b00091cb8361662e8d51")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 15 * 24 * 60  # 15 days
    REFRESH_COOKIE_NAME: str = "refresh"

    REDIS_HOST: str = environ.get("REDIS_HOST", "localhost")
    REDIS_PORT: str = environ.get("REDIS_PORT", 6379)


settings = Settings()
