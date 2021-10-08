from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from verify_jwt import verify_jwt


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            error, payload = verify_jwt(credentials.credentials)
            if error:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Invalid token: {error}")
            return payload
        else:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token")
