import os
import asyncio
import httpx
from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import JWTError, jwt

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

# Global Cache for OpenID Config and JWKS
openid_config = None
jwks = None

async def fetch_openid_config():
    """Fetch and cache OpenID Configuration and JWKS"""
    global openid_config, jwks
    async with httpx.AsyncClient() as client:
        response = await client.get(OPENID_CONFIG_URL)
        if response.status_code != 200:
            raise Exception("Failed to fetch OpenID configuration")
        openid_config = response.json()
    
    # Fetch and cache JWKS keys
    jwks_uri = openid_config["jwks_uri"]
    async with httpx.AsyncClient() as client:
        response = await client.get(jwks_uri)
        if response.status_code != 200:
            raise Exception("Failed to fetch JWKS keys")
        jwks = response.json()

# Run fetching task on startup
@app.on_event("startup")
async def startup_event():
    await fetch_openid_config()

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Extract and validate token"""
    try:
        # Ensure OpenID Config and JWKS are loaded
        if openid_config is None or jwks is None:
            await fetch_openid_config()

        # Decode JWT header
        header = jwt.get_unverified_header(token)
        key = next((key for key in jwks["keys"] if key["kid"] == header["kid"]), None)
        if key is None:
            raise HTTPException(status_code=401, detail="Invalid token: No matching key found")

        # Verify the token using the key
        payload = jwt.decode(token, jwt.algorithms.RSAAlgorithm.from_jwk(key), audience=CLIENT_ID, algorithms=["RS256"])

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
