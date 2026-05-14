import os
import logging
import json
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.sessions import SessionMiddleware

# Authlib Starlette integration

from dataone.auth import (
    AuthFactory,
    load_client_secrets,
    get_access_mode
)

from pydantic import BaseModel

ACCESS_MODE_AUTHENTICATED = "authenticated"
logger = logging.getLogger(__name__)

app = FastAPI(title="DataONE OIDC API")

# Starlette needs SessionMiddleware to store OIDC state/nonce
app.add_middleware(
    SessionMiddleware, 
    secret_key=os.getenv("SECRET_KEY", os.urandom(32).hex())
)

try:
    secrets = load_client_secrets()
except (FileNotFoundError, json.JSONDecodeError) as exc:
    logger.warning("Could not load client secrets (%s). Auth unavailable.", exc)
    secrets = {}

scopes = ["ogdc:admin"]
auth_adapter = AuthFactory.create_client("fastapi", secrets, scopes)
oidc_client = auth_adapter.dataone_oidc


security = HTTPBearer()

def validate_scope(required_scope: str, methods=None):
    """Factory for scope validation dependencies."""
    async def scope_checker(
        request: Request,
        auth: Optional[HTTPAuthorizationCredentials] = Depends(security)
    ):
        mode = get_access_mode()
        
        if mode != ACCESS_MODE_AUTHENTICATED:
            logger.warning("Access mode '%s': skipping scope validation", mode)
            return None

        if methods is not None and request.method not in methods:
            return None
        
        if not auth or not auth.credentials:
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

        try:
            claims = await auth_adapter.validate_and_extract_claims(
                token_str=auth.credentials, 
                required_scope=required_scope
            )
            return claims
        except Exception as e:
            error_response = auth_adapter.error_handler(e)
            raise HTTPException(
                status_code=error_response.status_code,
                detail=json.loads(error_response.body.decode())["error"]
            )
    return scope_checker


class RefreshRequest(BaseModel):
    refresh_token: str
    scope: Optional[str] = None


@app.get("/login")
async def login(request: Request):
    """Initiate OIDC login flow."""
    # Build redirect_uri using request.url_for
    redirect_uri = request.url_for("authorize")
    try:
        return await oidc_client.authorize_redirect(request, str(redirect_uri))
    except Exception as exc:
        logger.warning("OIDC authorize_redirect error: %s", exc)
        return auth_adapter.error_handler(exc)

@app.get("/authorize")
async def authorize(request: Request):
    """OIDC callback."""
    try:
        token = await oidc_client.authorize_access_token(request)
        return {
            "message": "Authorization successful",
            "token": {
                "access_token": token.get("access_token"),
                "refresh_token": token.get("refresh_token"),
            }
        }
    except Exception as exc:
        return auth_adapter.error_handler(exc)

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

@app.get("/profile")
async def profile(claims: Optional[dict] = Depends(validate_scope("ogdc:admin"))):
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

@app.post("/refresh")
async def refresh_token(body: RefreshRequest):
    """Refresh token exchange."""
    try:
        kwargs = {
            "grant_type": "refresh_token",
            "refresh_token": body.refresh_token,
        }
        if body.scope:
            kwargs["scope"] = body.scope

        new_tokens = await oidc_client.fetch_access_token(**kwargs)
        
        return {
            "message": "Authorization successful",
            "token": {
                "access_token": new_tokens.get("access_token"),
                "refresh_token": new_tokens.get("refresh_token"),
            }
        }
    except Exception as exc:
        logger.error("Unexpected Exception during refresh: %s", exc, exc_info=True)
        return auth_adapter.error_handler(exc)

if __name__ == "__main__":
    import uvicorn
    # Use proxy_headers=True to handle Kubernetes Ingress headers (X-Forwarded-For, etc.)
    uvicorn.run(app, host="0.0.0.0", port=4000, proxy_headers=True, forwarded_allow_ips="*")