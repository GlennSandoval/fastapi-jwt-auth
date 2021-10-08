import json
import urllib.request
from typing import Optional

from jose import jwt, JWTError
from jose.exceptions import JWTClaimsError

from config import settings

auth_settings = settings.get("auth")

jwks_url = auth_settings.get("jwks_url")
audience = auth_settings.get("audience")

# Get the public keys needed to verify JWT tokens
with urllib.request.urlopen(jwks_url) as url:
    jwks: dict = json.loads(url.read().decode()) or {}

# Arrange the keys in a dict keyed on the 'kid' for convenient lookup
keys: list = jwks["keys"]
kid_dict = dict((k['kid'], k) for k in keys)


def verify_jwt(jwtoken: str) -> tuple[Optional[Exception], Optional[dict]]:
    """Verifies a JWT token

    :param jwtoken: The token to verify
    :return: An error if any and the contents of the token if valid
    """
    try:
        kid: str = jwt.get_unverified_header(jwtoken)['kid']
        rsa_key = kid_dict[kid] or {}
        payload = jwt.decode(jwtoken, rsa_key, algorithms=['RS256'], audience=audience)
        error = None
    except (JWTError, JWTClaimsError) as jwt_error:
        payload = None
        error = jwt_error

    return error, payload


if __name__ == "__main__":
    e, p = verify_jwt(
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjNIdkNhTFZQN3NEZVJKWURLTVNQbSJ9.eyJpc3MiOiJodHRwczovL3NhbmRvdmFsLmF1LmF1dGgwLmNvbS8iLCJzdWIiOiIxNTdnWDJoemY3bW5IblVhM1YxYW1CZHRpQVVlelU3UUBjbGllbnRzIiwiYXVkIjoiaHR0cHM6Ly9mYXN0YXBpLWRlbW8uaW8iLCJpYXQiOjE2MzM1Njg4MTksImV4cCI6MTYzMzY1NTIxOSwiYXpwIjoiMTU3Z1gyaHpmN21uSG5VYTNWMWFtQmR0aUFVZXpVN1EiLCJzY29wZSI6InJlYWQ6YWxsIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIiwicGVybWlzc2lvbnMiOlsicmVhZDphbGwiXX0.koMxR3WnFh3kVdyL_IdrHsacnPhomtBX0IR49mbxgIGyKe4BDD90d_PuzMm3E3eRrtrMVCGgCZuFzrfbSsQz2CLK_bY4HFCorivSl13rjd9iODbkRkYHJFRSXXYFwFX1dvoiTuu4lGHy1gO4b9Q1e7-ypG4uM7sf7r0_HWGfkNO2n4wlqldq5f2Ajok6E1Hjb3YMpv1s-HJ12jQsG9ks_wu1nCbOawyw-N9-G0GfT7kXewVGL5PmJk6mQJH22zxNVLOZXELWLnvyYOc5w4Uea7JwfUA4JAUj6FRkZkA5-nM12H31jCoMwY0mutlyvC9ZO51Zvtovyqjs5G-XHM5Yrg')
    print("Error", e)
    if p:
        print("Permissions", p.get("permissions"))
