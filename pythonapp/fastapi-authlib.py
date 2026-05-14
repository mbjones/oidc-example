import json
import logging
import os
from typing import Optional

from fastapi import Depends, FastAPI, Request
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from dataone.auth import AuthFactory, load_client_secrets

# --- Constants & Logging ---
ACCESS_MODE_AUTHENTICATED = "authenticated"
scopes = ["ogdc:admin"]
logger = logging.getLogger(__name__)


# --- Models ---
class RefreshRequest(BaseModel):
    refresh_token: str
    scope: Optional[str] = None

class ProfileResponse(BaseModel):
    sub: str
    iss: str
    aud: str
    azp: Optional[str] = None
    exp: int
    iat: int
    nbf: Optional[int] = None
    jti: Optional[str] = None
    scope: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    preferred_username: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None


# --- App Initialization ---
app = FastAPI(title="DataONE OIDC API")

# Starlette needs SessionMiddleware to store OIDC state/nonce
app.add_middleware(
    SessionMiddleware, 
    secret_key=os.getenv("SECRET_KEY", os.urandom(32).hex())
)

# --- Auth Setup ---
try:
    secrets = load_client_secrets()
except (FileNotFoundError, json.JSONDecodeError) as exc:
    logger.warning("Could not load client secrets (%s). Auth unavailable.", exc)
    secrets = {}

auth_adapter = AuthFactory.create_client("fastapi", secrets, scopes)
oidc_client = auth_adapter.dataone_oidc
security = HTTPBearer()


# --- Routes ---
@app.get("/login")
async def login(request: Request):
    # One line: Redirect to Keycloak
    return await auth_adapter.login(
        request=request,
        redirect_uri=str(request.url_for("authorize"))
    )

@app.get("/authorize")
async def authorize(request: Request):
    # One line: Exchange code for token and return JSON
    return await auth_adapter.authorize(request=request)

@app.post("/refresh")
async def refresh(request: Request):
    # One line: Extract body, refresh, and return JSON
    body = await request.json()
    return await auth_adapter.refresh(body)

@app.get("/profile")
async def profile(claims: Optional[dict] = Depends(auth_adapter.require_scope("ogdc:admin"))):
    """
    Protected resource endpoint.
    """
    if claims is None:
        return {
            "message": "Authorization bypassed (open/read-only mode)",
            "claims": {}
        }
    
    profile_data = ProfileResponse(**claims)
    
    return {
        "message": f"Authorization succeeded, {claims.get('name', 'User')}",
        "claims": profile_data.model_dump()
    }


# --- Execution ---
if __name__ == "__main__":
    import uvicorn
    # Use proxy_headers=True to handle Kubernetes Ingress headers (X-Forwarded-For, etc.)
    uvicorn.run(app, host="0.0.0.0", port=4000, proxy_headers=True, forwarded_allow_ips="*")