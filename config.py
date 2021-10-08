import os

from dotenv import load_dotenv

load_dotenv()

settings: dict = {
    "auth": {
        "audience": os.getenv("AUDIENCE"),
        "jwks_url": os.getenv("JWKS_URL")
    }

}
