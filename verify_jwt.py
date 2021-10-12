"""
Provide a method to verify a jwt against the audience and public keys specified in the config.
"""

import json
import urllib.request
from typing import Optional

from jose import jwt, JWTError  # type: ignore
from jose.exceptions import JWTClaimsError  # type: ignore

from config import settings

auth_settings: dict[str, str] = settings.get("auth") or {}

jwks_url: str = auth_settings.get("jwks_url") or ""
audience: str = auth_settings.get("audience") or ""

# Get the public keys needed to verify JWT tokens
with urllib.request.urlopen(jwks_url) as url:
    jwks: dict = json.loads(url.read().decode()) or {}

# Arrange the keys in a dict keyed on the 'kid' for convenient lookup
keys: list = jwks["keys"]
kid_dict = dict((k["kid"], k) for k in keys)


def verify_jwt(jwtoken: str) -> tuple[Optional[dict], Optional[Exception]]:
    """Verifies a JWT token

    :param jwtoken: The token to verify
    :return: An error if any and the contents of the token if valid
    """
    try:
        kid: str = jwt.get_unverified_header(jwtoken)["kid"]
        rsa_key = kid_dict[kid] or {}
        payload = jwt.decode(jwtoken, rsa_key, algorithms=["RS256"], audience=audience)
        error = None
    except (JWTError, JWTClaimsError) as jwt_error:
        payload = None
        error = jwt_error

    return payload, error
