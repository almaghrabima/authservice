# config.py
from pydantic_settings import BaseSettings  # Updated import for Pydantic v2
from pydantic import Field
from functools import lru_cache
from typing import Optional

class Settings(BaseSettings):
    # Auth0 Configurations
    auth0_domain: str = Field(..., env='AUTH0_DOMAIN')
    auth0_api_audience: str = Field(..., env='AUTH0_API_AUDIENCE')
    auth0_client_id: str = Field(..., env='AUTH0_CLIENT_ID')
    auth0_client_secret: str = Field(..., env='AUTH0_CLIENT_SECRET')
    auth0_mgmt_client_id: str = Field(..., env='AUTH0_MGMT_CLIENT_ID')
    auth0_mgmt_client_secret: str = Field(..., env='AUTH0_MGMT_CLIENT_SECRET')
    auth0_issuer: str = Field(..., env='AUTH0_ISSUER')
    auth0_algorithms: str = Field(..., env='AUTH0_ALGORITHMS')
    
    # Redis Configurations
    redis_host: str = Field("redis-stack", env='REDIS_HOST')  # Default to 'redis-stack'
    redis_port: int = Field(6379, env='REDIS_PORT')
    redis_db: int = Field(0, env='REDIS_DB')
    redis_username: Optional[str] = Field(None, env='REDIS_USERNAME')  # <-- Added username
    redis_password: Optional[str] = Field(None, env='REDIS_PASSWORD')  # Renamed for clarity
    redis_ssl: bool = Field(False, env='REDIS_SSL')  # <-- Added SSL setting
    
    # Optional: for redirecting after login
    application_url: Optional[str] = None  # Optional: for redirecting after logout

    class Config:
        env_file = ".env"  # Ensure you have a .env file with these variables

@lru_cache()
def get_settings() -> Settings:
    return Settings()