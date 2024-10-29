# utils.py

from typing import Optional
from functools import lru_cache
import jwt
from jwt.exceptions import PyJWKClientError, DecodeError
from fastapi import Depends, HTTPException, status
from fastapi.security import SecurityScopes, HTTPAuthorizationCredentials, HTTPBearer
import requests

from config import get_settings, Settings
from redis_config import get_redis_client

import httpx
import logging

logger = logging.getLogger(__name__)

class UnauthorizedException(HTTPException):
    def __init__(self, detail: str, **kwargs):
        """Returns HTTP 403 Forbidden"""
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

class UnauthenticatedException(HTTPException):
    def __init__(self):
        """Returns HTTP 401 Unauthorized"""
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Requires authentication"
        )

class VerifyToken:
    """Handles token verification using PyJWT and Redis caching"""

    def __init__(self):
        self.config = get_settings()

        # Get JWKS from Auth0
        jwks_url = f'https://{self.config.auth0_domain}/.well-known/jwks.json'
        self.jwks_client = jwt.PyJWKClient(jwks_url)
        self.redis_client = get_redis_client()

    async def verify(
        self,
        security_scopes: Optional[SecurityScopes] = None,
        token: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer())
    ):
        if token is None:
            raise UnauthenticatedException

        token_str = token.credentials

        # Check Redis cache first
        cache_key = f"token:{token_str}"
        cached_payload = self.redis_client.get(cache_key)
        if cached_payload:
            try:
                payload = jwt.decode(
                    cached_payload,
                    options={"verify_signature": False},
                    algorithms=[self.config.auth0_algorithms],
                )
                return payload
            except Exception:
                # If decoding fails, proceed to verify the token normally
                pass

        # Verify the token with Auth0's JWKS
        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(token_str).key
        except (PyJWKClientError, DecodeError) as error:
            raise UnauthorizedException(str(error))

        try:
            payload = jwt.decode(
                token_str,
                signing_key,
                algorithms=[self.config.auth0_algorithms],
                audience=self.config.auth0_api_audience,
                issuer=self.config.auth0_issuer,
            )
            # Cache the payload in Redis for 1 hour (3600 seconds)
            self.redis_client.setex(
                cache_key, 3600, jwt.encode(payload, key="", algorithm="none")
            )
        except jwt.PyJWTError as error:
            raise UnauthorizedException(str(error))

        return payload

# def get_auth0_mgmt_token():
#     """
#     Retrieves an Auth0 Management API token using client credentials.
#     """
#     config = get_settings()
#     payload = {
#         'grant_type': 'client_credentials',
#         'client_id': config.auth0_mgmt_client_id,
#         'client_secret': config.auth0_mgmt_client_secret,
#         'audience': f'https://{config.auth0_domain}/api/v2/'
#     }

#     response = requests.post(
#         f'https://{config.auth0_domain}/oauth/token',
#         json=payload,
#         headers={'Content-Type': 'application/json'}
#     )

#     if response.status_code != 200:
#         raise Exception(f"Failed to get Auth0 Management API token: {response.text}")

#     token = response.json()['access_token']
#     return token


async def get_auth0_mgmt_token(config: Settings = Depends(get_settings)) -> str:
    """
    Asynchronously retrieve Auth0 Management API token using client credentials grant.
    """
    token_url = f"https://{config.auth0_domain}/oauth/token"
    payload = {
        "client_id": config.auth0_mgmt_client_id,
        "client_secret": config.auth0_mgmt_client_secret,
        "audience": f"https://{config.auth0_domain}/api/v2/",
        "grant_type": "client_credentials"
    }
    headers = {
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(token_url, json=payload, headers=headers)
            response.raise_for_status()
            token = response.json().get("access_token")
            if not token:
                logger.error("Auth0 Management token not found in response.")
                raise Exception("Token retrieval failed.")
            return token
        except httpx.HTTPError as http_err:
            logger.error(f"HTTP error occurred while retrieving Auth0 Management token: {http_err}")
            raise Exception("Token retrieval failed.")
        except Exception as err:
            logger.error(f"An error occurred while retrieving Auth0 Management token: {err}")
            raise Exception("Token retrieval failed.")