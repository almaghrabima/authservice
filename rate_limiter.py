# rate_limiter.py
from fastapi import Request, HTTPException, status
import redis.asyncio as redis
import logging

from redis_config import get_redis_client

# Configuration for rate limiting
RATE_LIMIT = 100  # Number of allowed requests
RATE_LIMIT_WINDOW = 60  # Time window in seconds

async def rate_limiter(request: Request, redis_client: redis.Redis):
    """
    Simple rate limiter using Redis.
    Limits the number of requests per IP address within a time window.
    """
    try:
        # Identify the client by IP address
        client_ip = request.client.host
        key = f"rate_limit:{client_ip}"
        
        # Increment the count for this IP
        current = await redis_client.incr(key)
        
        if current == 1:
            # Set the expiration time for the key
            await redis_client.expire(key, RATE_LIMIT_WINDOW)
        
        if current > RATE_LIMIT:
            # If the limit is exceeded, raise an exception
            logging.warning(f"Rate limit exceeded for IP: {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later."
            )
    except redis.RedisError as e:
        # Log the error and allow the request to proceed
        logging.error(f"Redis error during rate limiting: {e}")
        # Optionally, you can decide to raise an exception or allow the request
        # Here, we'll allow the request to proceed in case of Redis failure
