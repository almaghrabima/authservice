# redis_config.py
import redis.asyncio as redis
from functools import lru_cache

from config import Settings, get_settings

@lru_cache()
def get_redis_client() -> redis.Redis:
    settings: Settings = get_settings()
    return redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        db=settings.redis_db,
        username=settings.redis_username,  # <-- Added username
        password=settings.redis_password,
        decode_responses=True,  # Automatically decode responses to strings
        encoding="utf-8",
        ssl=settings.redis_ssl  # Use the redis_ssl setting
    )
