"""
A dependency class to allow FastAPI endpoints to validate a JWT
"""
from typing import Optional

from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from verify_jwt import verify_jwt


class JWTBearer(HTTPBearer):  # pylint: disable=too-few-public-methods
    """
    Get and validate the JWT token in the Auth header
    """

    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: Optional[HTTPAuthorizationCredentials] = await super().__call__(
            request
        )
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token"
            )

        payload, error = verify_jwt(credentials.credentials)
        if error:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Invalid token: {error}",
            )
        return payload
