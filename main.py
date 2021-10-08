import uvicorn
from fastapi import FastAPI, Depends

from jwt_bearer import JWTBearer

app = FastAPI()
auth = JWTBearer()


@app.get("/", tags=["root"])
async def root() -> dict:
    return {"message": "Hello World"}


@app.get("/secure", tags=["secured"])
async def secure(payload=Depends(auth)) -> dict:
    return payload


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
