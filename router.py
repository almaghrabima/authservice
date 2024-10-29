# Description: This file contains the FastAPI router for the authentication service.
from fastapi import Request, APIRouter, Depends, Body, Path, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, HTTPBearer, HTTPAuthorizationCredentials
from authlib.integrations.httpx_client import AsyncOAuth2Client
from uuid import UUID
import json
import re
import logging
import redis.asyncio as redis
import jwt  # PyJWT library
from utils import VerifyToken, get_auth0_mgmt_token, get_settings
from models import UserCreate, UserUpdate, TokenData, User, EmailVerificationRequest, LogoutRequest
from redis_config import get_redis_client
from config import Settings
from urllib.parse import urlencode, quote_plus
import os
from fastapi.responses import FileResponse




router = APIRouter()
auth = VerifyToken()
config = get_settings()

security = HTTPBearer()

    
def sanitize_user_id(user_id: str) -> str:
    user_id = user_id.split('@')[0]
    if not any(prefix in user_id for prefix in ['auth0|', 'google-oauth2|']):
        user_id = f'auth0|{user_id}'
    return user_id

async def get_current_user(
    token: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    redis_client: redis.Redis = Depends(get_redis_client)
):
    try:
        is_revoked = await redis_client.get(f"revoked_token:{token.credentials}")
        if is_revoked:
            logging.error("Token has been revoked")
            raise HTTPException(status_code=401, detail="Token has been revoked")
        
        payload = await auth.verify(token=token)
        if not payload or 'sub' not in payload:
            logging.error("Invalid token payload")
            raise HTTPException(status_code=401, detail="Invalid token")
            
        logging.info(f"Token payload: {payload}")
        return payload
    except Exception as e:
        logging.error(f"Error verifying token: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

@router.post("/register", response_model=User, status_code=status.HTTP_201_CREATED)
async def register(
    user: UserCreate,
    config: Settings = Depends(get_settings),
    token: str = Depends(get_auth0_mgmt_token),
    redis_client: redis.Redis = Depends(get_redis_client)
):
    logging.info("Starting user registration process")
    
    phone_pattern = r"^\+966\d{9}$"
    if not re.match(phone_pattern, user.phone_number):
        logging.error(f"Invalid phone number format: {user.phone_number}")
        raise HTTPException(
            status_code=400, 
            detail="Phone number must start with '+966' followed by nine digits."
        )
    
    # Wrap the token in a dictionary format expected by authlib
    token_dict = {
        "access_token": token,
        "token_type": "Bearer"
    }
    
    user_data = {
        "email": user.email,
        "password": user.password,
        "connection": "Username-Password-Authentication",
        "username": user.username,
        "user_metadata": {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "phone_number": user.phone_number
        }
    }
    
    async with AsyncOAuth2Client(token=token_dict) as client:
        client.headers.update({'Content-Type': 'application/json'})
        
        try:
            response = await client.post(
                f'https://{config.auth0_domain}/api/v2/users',
                json=user_data
            )
            response.raise_for_status()
            created_user = response.json()
            auth0_user_id = created_user.get('user_id', '')

            await redis_client.set(
                f"user:{auth0_user_id}",
                json.dumps(created_user),
                ex=3600  # Expiration time in seconds
            )
            logging.info(f"Cached user data for {auth0_user_id}")
            
            # Send verification email
            verification_data = {
                "user_id": auth0_user_id,
                "client_id": config.auth0_client_id
            }
            verify_response = await client.post(
                f'https://{config.auth0_domain}/api/v2/jobs/verification-email',
                json=verification_data
            )
            verify_response.raise_for_status()
            logging.info("Verification email sent during registration")
        
        except Exception as e:
            logging.error(f"Registration or verification email failed: {str(e)}")
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
    
    return User(
        id=auth0_user_id,
        email=created_user['email'],
        username=created_user.get('username', ''),
        first_name=user.first_name,
        last_name=user.last_name,
        phone_number=user.phone_number
    )
    
@router.post("/verify_email")
async def verify_email(
    user: EmailVerificationRequest,
    config: Settings = Depends(get_settings),
    token: str = Depends(get_auth0_mgmt_token),
    redis_client: redis.Redis = Depends(get_redis_client)
):
    """
    Trigger an email verification email for a specific email address.
    """
    email = user.email
    logging.info(f"Starting email verification process for email: {email}")
    
    # Wrap the token in a dictionary format expected by authlib
    token_dict = {
        "access_token": token,
        "token_type": "Bearer"
    }

    async with AsyncOAuth2Client(token=token_dict) as client:
        client.headers.update({'Content-Type': 'application/json'})
        
        # Step 1: Search for the user by email
        search_url = f'https://{config.auth0_domain}/api/v2/users-by-email'
        search_params = {'email': email}
        
        try:
            search_response = await client.get(search_url, params=search_params)
            search_response.raise_for_status()
        except Exception as exc:
            logging.error(f"Error during user search request: {exc}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable."
            )
        
        users = search_response.json()
        if not users:
            logging.error(f"No user found with email: {email}")
            raise HTTPException(status_code=404, detail="User not found")

        user_id = users[0].get('user_id')
        if not user_id:
            logging.error(f"user_id not found for email: {email}")
            raise HTTPException(status_code=500, detail="Invalid user data received")

        logging.info(f"Found user_id: {user_id}")

        # Step 2: Send verification email
        data = {
            "user_id": user_id,
            "client_id": config.auth0_client_id
        }

        verify_url = f'https://{config.auth0_domain}/api/v2/jobs/verification-email'

        try:
            verify_response = await client.post(verify_url, json=data)
            verify_response.raise_for_status()
            logging.info("Verification email sent successfully")
        except Exception as exc:
            logging.error(f"Error sending verification email: {exc}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable."
            )

        return {"message": "Verification email sent successfully"}

@router.post("/login", response_model=TokenData, status_code=status.HTTP_200_OK)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    config: Settings = Depends(get_settings),
    redis_client: redis.Redis = Depends(get_redis_client)
):
    """
    Authenticate a user and provide access tokens with caching in Redis.
    """
    logging.info(f"Starting login process for user: {form_data.username}")
    
    # Attempt to retrieve user data from cache (optional)
    try:
        cached_user = await redis_client.get(f"user:{form_data.username}")
        if cached_user:
            user_data = json.loads(cached_user)
            logging.info("User data retrieved from cache")
    except Exception as e:
        logging.error(f"Failed to retrieve user data from cache: {str(e)}")

    # OAuth2 payload for password grant type
    token_url = f'https://{config.auth0_domain}/oauth/token'
    client = AsyncOAuth2Client(
        client_id=config.auth0_client_id,
        client_secret=config.auth0_client_secret,
        scope='openid profile email offline_access',
        token_endpoint_auth_method='client_secret_post'
    )

    try:
        # Fetch token from Auth0
        token_response = await client.fetch_token(
            url=token_url,
            grant_type='password',
            username=form_data.username,
            password=form_data.password,
            audience=config.auth0_api_audience
        )
    except Exception as exc:
        logging.error(f"Authentication request error: {exc}")
        # Attempt to get the response content for debugging
        response_content = ''
        if hasattr(exc, 'response') and exc.response is not None:
            response_content = await exc.response.text()
        logging.error(f"Auth0 Response Content (if available): {response_content or 'No response'}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable."
        )

    # Ensure access token is in the response
    if 'access_token' not in token_response:
        logging.error("Access token not found in the response.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service did not return an access token."
        )

    logging.info(f"Authentication successful for user: {form_data.username}")

    # Optionally, cache the token or related data
    try:
        await redis_client.set(
            f"token:{token_response['access_token']}",
            form_data.username,
            ex=token_response.get('expires_in', 3600)
        )
        logging.info("Cached access token")
    except Exception as e:
        logging.error(f"Failed to cache access token: {str(e)}")

    return TokenData(
        access_token=token_response.get('access_token'),
        refresh_token=token_response.get('refresh_token'),
        id_token=token_response.get('id_token'),
        token_type=token_response.get('token_type'),
        expires_in=token_response.get('expires_in')
    )

@router.post("/logout", response_class=FileResponse)
async def logout(
    logout_request: LogoutRequest = Body(default=None),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    redis_client: redis.Redis = Depends(get_redis_client),
    settings: Settings = Depends(get_settings)
):
    """
    Complete logout flow:
    1. Revoke the current access token locally (Redis blacklist)
    2. Revoke refresh token with Auth0 if provided
    3. Call Auth0's v2 logout endpoint to terminate the Auth0 session
    4. Return the post-logout HTML page
    """
    access_token = credentials.credentials

    # Step 1: Blacklist the current access token in Redis
    try:
        ttl = 3600  # 1 hour TTL for the blacklist
        await redis_client.set(f"revoked_token:{access_token}", "revoked", ex=ttl)
        logging.info("Access token blacklisted successfully")
    except Exception as e:
        logging.error(f"Failed to blacklist access token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke access token"
        )

    # Step 2: Revoke refresh token if provided
    if logout_request and logout_request.refresh_token:
        try:
            async with AsyncOAuth2Client(
                client_id=settings.auth0_client_id,
                client_secret=settings.auth0_client_secret
            ) as client:
                revoke_url = f"https://{settings.auth0_domain}/oauth/revoke"
                payload = {
                    'client_id': settings.auth0_client_id,
                    'client_secret': settings.auth0_client_secret,
                    'token': logout_request.refresh_token,
                    'token_type_hint': 'refresh_token'
                }
                response = await client.post(revoke_url, data=payload)
                if response.status_code != 200:
                    logging.error(f"Failed to revoke refresh token: {response.status_code}")
                else:
                    logging.info("Refresh token revoked successfully")
        except Exception as e:
            logging.error(f"Error revoking refresh token: {str(e)}")

    # Step 3: Call Auth0's v2 logout endpoint
    try:
        # Make sure this returnTo URL is listed in Auth0's Allowed Logout URLs
        return_to_url = f"{settings.application_url}/post-logout"
        encoded_return_to = quote_plus(return_to_url)
        
        auth0_logout_url = (
            f"https://{settings.auth0_domain}/v2/logout?"
            f"client_id={settings.auth0_client_id}&"
            f"returnTo={encoded_return_to}&"
            "federated"  # Add this to also logout from the identity provider
        )
        
        async with AsyncOAuth2Client() as client:
            logging.info(f"Calling Auth0 logout URL: {auth0_logout_url}")
            await client.get(auth0_logout_url)
            logging.info("Auth0 logout successful")
            
    except Exception as e:
        logging.error(f"Error during Auth0 logout: {str(e)}")
        # Continue to return the logout page even if Auth0 logout fails

    # Step 4: Return post-logout page
    try:
        file_path = os.path.join(os.path.dirname(__file__), "post-logout.html")
        if not os.path.exists(file_path):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Logout page not found"
            )
        return FileResponse(
            path=file_path, 
            media_type='text/html',
            headers={
                "Location": auth0_logout_url,  # Add Auth0 logout URL as header
                "X-Auth0-Logout-URL": auth0_logout_url  # Custom header for client processing
            }
        )
    except Exception as e:
        logging.error(f"Error serving logout page: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to serve logout page"
        )

@router.get("/check-auth-status")
async def check_auth_status(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    settings: Settings = Depends(get_settings)
):
    """
    Check if user is still logged in with Auth0
    Returns:
        - logged_in: True/False indicating if user's Auth0 session is active
        - message: Description of the auth status
    """
    access_token = credentials.credentials

    # Create Auth0 userinfo endpoint URL
    userinfo_url = f"https://{settings.auth0_domain}/userinfo"

    async with AsyncOAuth2Client(token={"access_token": access_token, "token_type": "Bearer"}) as client:
        try:
            response = await client.get(userinfo_url)
            
            if response.status_code == 200:
                return {
                    "logged_in": True,
                    "message": "User is logged in",
                    "user_info": response.json()
                }
            else:
                return {
                    "logged_in": False,
                    "message": "User is not logged in or session has expired"
                }
                
        except Exception as e:
            logging.error(f"Error checking Auth0 session: {str(e)}")
            return {
                "logged_in": False,
                "message": "Failed to verify authentication status",
                "error": str(e)
            }
            
@router.get("/user", response_model=User)
async def get_user(
    current_user=Depends(get_current_user),
    redis_client: redis.Redis = Depends(get_redis_client),
    config: Settings = Depends(get_settings),
    token: str = Depends(get_auth0_mgmt_token)
):
    """
    Get the current user's profile information.
    """
    user_id = current_user['sub']
    cache_key = f"user:{user_id}"

    # Step 1: Attempt to retrieve user data from Redis
    try:
        cached_user = await redis_client.get(cache_key)
        if cached_user:
            logging.info("User data retrieved from cache")
            user_info = json.loads(cached_user)
            return User(
                id=user_info['user_id'],
                email=user_info['email'],
                username=user_info.get('username', ''),
                first_name=user_info.get('user_metadata', {}).get('first_name', ''),
                last_name=user_info.get('user_metadata', {}).get('last_name', ''),
                phone_number=user_info.get('user_metadata', {}).get('phone_number', '')
            )
    except Exception as e:
        logging.error(f"Failed to retrieve user data from cache: {str(e)}")

    # Step 2: Retrieve user information from Auth0 if not found in Redis
    async with AsyncOAuth2Client(token={"access_token": token, "token_type": "Bearer"}) as client:
        try:
            response = await client.get(
                f'https://{config.auth0_domain}/api/v2/users/{user_id}'
            )
            response.raise_for_status()
            user_info = response.json()
        except Exception as e:
            logging.error(f"Failed to fetch user data from Auth0: {str(e)}")
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Failed to fetch user data")

    # Step 3: Cache the user data in Redis for future requests
    try:
        await redis_client.set(cache_key, json.dumps(user_info), ex=3600)  # Cache for 1 hour
        logging.info("User data cached successfully")
    except Exception as e:
        logging.error(f"Failed to cache user data: {str(e)}")

    # Return the user profile
    return User(
        id=user_info['user_id'],
        email=user_info['email'],
        username=user_info.get('username', ''),
        first_name=user_info.get('user_metadata', {}).get('first_name', ''),
        last_name=user_info.get('user_metadata', {}).get('last_name', ''),
        phone_number=user_info.get('user_metadata', {}).get('phone_number', '')
    )

@router.put("/user", response_model=User)
async def update_user(
    user_update: UserUpdate,
    current_user=Depends(get_current_user),
    config: Settings = Depends(get_settings),
    token: str = Depends(get_auth0_mgmt_token),
    redis_client: redis.Redis = Depends(get_redis_client)
):
    """
    Update the current user's profile information.
    """
    user_id = current_user['sub']
    cache_key = f"user:{user_id}"
    data = {}

    # Prepare the data to update
    if user_update.email:
        data['email'] = user_update.email
    if user_update.password:
        data['password'] = user_update.password
    if user_update.username:
        data['username'] = user_update.username

    user_metadata = {}
    if user_update.first_name:
        user_metadata['first_name'] = user_update.first_name
    if user_update.last_name:
        user_metadata['last_name'] = user_update.last_name
    if user_update.phone_number:
        user_metadata['phone_number'] = user_update.phone_number

    if user_metadata:
        data['user_metadata'] = user_metadata

    # Update the user's information in Auth0
    async with AsyncOAuth2Client(token={"access_token": token, "token_type": "Bearer"}) as client:
        try:
            response = await client.patch(
                f'https://{config.auth0_domain}/api/v2/users/{user_id}',
                json=data
            )
            response.raise_for_status()
            updated_user = response.json()
        except Exception as e:
            logging.error(f"Failed to update user data in Auth0: {str(e)}")
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Failed to update user data")

    # Step 3: Update the user data in Redis if it exists
    try:
        cached_user = await redis_client.get(cache_key)
        if cached_user:
            await redis_client.set(cache_key, json.dumps(updated_user), ex=3600)  # Cache for 1 hour
            logging.info("User data in Redis cache updated successfully")
    except Exception as e:
        logging.error(f"Failed to update user data in Redis: {str(e)}")

    # Return the updated user profile
    return User(
        id=updated_user['user_id'],
        email=updated_user['email'],
        username=updated_user.get('username', ''),
        first_name=updated_user.get('user_metadata', {}).get('first_name', ''),
        last_name=updated_user.get('user_metadata', {}).get('last_name', ''),
        phone_number=updated_user.get('user_metadata', {}).get('phone_number', '')
    )

@router.post("/refresh_access_token", response_model=TokenData)
async def refresh_access_token(
    refresh_token: str = Body(None, embed=True),
    config: Settings = Depends(get_settings),
    redis_client: redis.Redis = Depends(get_redis_client)
):
    """
    Refresh the access token using an optional refresh token.
    If refresh token is not provided, request a new access token using client credentials.
    """
    payload = {
        'client_id': config.auth0_client_id,
        'client_secret': config.auth0_client_secret
    }

    if refresh_token:
        # Use the provided refresh token to request a new access token
        payload['grant_type'] = 'refresh_token'
        payload['refresh_token'] = refresh_token
    else:
        # If no refresh token, use client credentials to request a new access token
        payload['grant_type'] = 'client_credentials'
        payload['audience'] = config.auth0_api_audience

    # Use AsyncOAuth2Client to request a token
    async with AsyncOAuth2Client(
        client_id=config.auth0_client_id,
        client_secret=config.auth0_client_secret,
        scope='openid profile email offline_access'
    ) as client:
        try:
            response = await client.post(
                f'https://{config.auth0_domain}/oauth/token',
                data=payload
            )
            logging.info(f"Auth0 Response Status Code: {response.status_code}")
            logging.info(f"Auth0 Response Content: {response.text}")

            # Check for a successful status code
            if response.status_code != 200:
                error_detail = response.json() if response.content else {"error": "No response content"}
                logging.error(f"Auth0 Error Detail: {error_detail}")
                raise HTTPException(status_code=response.status_code, detail=error_detail)

            token_data = response.json()
        except Exception as e:
            logging.error(f"Failed to obtain access token: {str(e)}")
            logging.error(f"Auth0 Response: {response.text if 'response' in locals() else 'No response received'}")
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Failed to obtain access token")

    # Cache the new access token in Redis with an expiration time if available
    try:
        access_token = token_data['access_token']
        expires_in = token_data.get('expires_in', 3600)  # Default to 1 hour if not provided
        await redis_client.set(f"token:{access_token}", "valid", ex=expires_in)
        logging.info("New access token cached successfully in Redis")
    except Exception as e:
        logging.error(f"Failed to cache access token in Redis: {str(e)}")

    # Return the new token data
    return TokenData(
        access_token=access_token,
        refresh_token=token_data.get('refresh_token', refresh_token)  # Use the new refresh token if provided, else retain the old one
    )

@router.post("/change_password")
async def change_password(
    current_password: str = Body(...),
    new_password: str = Body(...),
    current_user=Depends(get_current_user),
):
    """
    Change the authenticated user's password.
    """
    config = get_settings()
    # Authenticate the user with current password
    auth_payload = {
        'grant_type': 'password',
        'username': current_user['email'],
        'password': current_password,
        'audience': config.auth0_api_audience,
        'scope': 'openid',
        'client_id': config.auth0_client_id,
        'client_secret': config.auth0_client_secret
    }

    auth_response = requests.post(f'https://{config.auth0_domain}/oauth/token', data=auth_payload)
    if auth_response.status_code != 200:
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Get Auth0 Management API token
    token = get_auth0_mgmt_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    user_id = current_user['sub']
    data = {
        "password": new_password,
        "connection": "Username-Password-Authentication"
    }

    response = requests.patch(
        f'https://{config.auth0_domain}/api/v2/users/{user_id}',
        headers=headers,
        json=data
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return {"message": "Password changed successfully"}

@router.post("/request_password_reset")
async def request_password_reset(email: str = Body(...)):
    """
    Request a password reset for a user.
    """
    config = get_settings()
    data = {
        "client_id": config.auth0_client_id,
        "email": email,
        "connection": "Username-Password-Authentication"
    }

    response = requests.post(
        f'https://{config.auth0_domain}/dbconnections/change_password',
        json=data
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return {"message": "Password reset email sent"}

@router.delete("/user/{user_id}", status_code=status.HTTP_200_OK)
async def delete_user(
    user_id: str = Path(..., description="The ID of the user to delete"),
    current_user=Depends(get_current_user),
    config: Settings = Depends(get_settings),
    token: str = Depends(get_auth0_mgmt_token),
    redis_client: redis.Redis = Depends(get_redis_client)
):
    """
    Delete a user account.
    Only the user themselves can delete their account.
    """
    # Authorization: Ensure the user is deleting their own account
    if user_id != current_user['sub']:
        logging.warning(f"Unauthorized delete attempt: user_id {user_id} by {current_user['sub']}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to delete this user")

    # Prepare headers for Auth0 API request
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    # Delete the user in Auth0 using AsyncOAuth2Client
    async with AsyncOAuth2Client(
        client_id=config.auth0_client_id,
        client_secret=config.auth0_client_secret
    ) as client:
        try:
            response = await client.delete(
                f'https://{config.auth0_domain}/api/v2/users/{user_id}',
                headers=headers
            )
            logging.info(f"Auth0 Response Status Code: {response.status_code}")
            logging.info(f"Auth0 Response Content: {response.text}")

            if response.status_code != 204:
                # Auth0 returns 204 No Content on successful deletion
                error_detail = response.json() if response.content else {"error": "No response content"}
                logging.error(f"Auth0 Error Detail: {error_detail}")
                raise HTTPException(status_code=response.status_code, detail=error_detail)
        except Exception as e:
            logging.error(f"Failed to delete user in Auth0: {str(e)}")
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Failed to delete user")

    # Remove user data from Redis cache if it exists
    cache_key = f"user:{user_id}"
    try:
        await redis_client.delete(cache_key)
        logging.info(f"User data removed from Redis cache: {cache_key}")
    except Exception as e:
        logging.error(f"Failed to remove user data from Redis cache: {str(e)}")
        # Not raising an exception here since the user has been deleted from Auth0

    return {"message": f"User {user_id} deleted successfully"}
