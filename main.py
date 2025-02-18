import os
from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import JWTError, jwt
import httpx


# Load environment variables
TENANT_ID = os.getenv("AZURE_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
OPENID_CONFIG_URL = f"{AUTHORITY}/.well-known/openid-configuration"

# OAuth2 Configuration
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{AUTHORITY}/oauth2/v2.0/authorize",
    tokenUrl=f"{AUTHORITY}/oauth2/v2.0/token"
)

app = FastAPI()

# Fetch OpenID config to get the signing keys for token verification
async def get_openid_config():
    async with httpx.AsyncClient() as client:
        response = await client.get(OPENID_CONFIG_URL)
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to fetch OpenID configuration")
        return response.json()

# Function to verify the token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        config = await get_openid_config()
        jwks_uri = config["jwks_uri"]

        # Fetch public keys
        async with httpx.AsyncClient() as client:
            jwks = (await client.get(jwks_uri)).json()

        # Decode JWT
        header = jwt.get_unverified_header(token)
        key = next((key for key in jwks["keys"] if key["kid"] == header["kid"]), None)
        if key is None:
            raise HTTPException(status_code=401, detail="Invalid token: No matching key found")

        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
        payload = jwt.decode(token, public_key, audience=CLIENT_ID, algorithms=["RS256"])

        return payload  # Returns the token payload (user info)

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Protected route
@app.get("/protected")
async def protected_route(user: dict = Depends(get_current_user)):
    return {"message": f"Hello {user['name']}, you are authenticated!"}

# Public route (does not require authentication)
@app.get("/")
def public_route():
    return {"message": "Public API is accessible without authentication"}
