# authmain.py
from fastapi import FastAPI, Request, HTTPException, status
from router import router
from rate_limiter import rate_limiter
import logging
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from redis_config import get_redis_client

# Initialize logging
logging.basicConfig(level=logging.INFO)

app = FastAPI()

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logging.error(f"HTTP error occurred: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )
    
# Apply global rate limiter as middleware
@app.middleware("http")
async def global_rate_limit(request: Request, call_next):
    try:
        # Retrieve the Redis client
        redis_client = get_redis_client()
        # Call the rate_limiter function with the request and Redis client
        await rate_limiter(request, redis_client)
    except HTTPException as exc:
        # If rate limit is exceeded, return the exception
        raise exc
    # Proceed to the next middleware or endpoint
    response = await call_next(request)
    return response

# Include your routers with the prefix "/api"
app.include_router(router, prefix="/api")

# Graceful shutdown event to close Redis client
@app.on_event("shutdown")
async def shutdown_event():
    redis_client = get_redis_client()
    await redis_client.close()
    logging.info("Redis client closed gracefully.")

# Entry point for Uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("authmain:app", host="0.0.0.0", port=8000, reload=True)
