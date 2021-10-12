"""
Example endpoints to demonstrate Auth bearer token validation
"""
import uvicorn  # type: ignore
from fastapi import FastAPI, Depends

from jwt_bearer import JWTBearer

app = FastAPI()
auth = JWTBearer()


@app.get("/", tags=["root"])
async def root() -> dict:
    """Simple 'Hello world' response"""
    return {"message": "Hello World"}


@app.get("/secure", tags=["secured"])
async def secure(payload=Depends(auth)) -> dict:
    """Secure endpoint example that requires a valid Auth token"""
    return payload


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
