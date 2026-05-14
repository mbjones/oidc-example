"""
A simple Flask application demonstrating OpenID Connect (OIDC) authentication
using the authlib library against a keycloak server. The application includes
only routes for accessing protected resources using only a token.

Call with: curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:4000/profile
"""

import json
import functools
import os
from requests import RequestException

from flask import (
    Flask,
    jsonify,
    request,
    url_for,
    current_app,
    g
)

from dataone.auth import (
    AuthFactory,
    load_client_secrets,
    extract_token_from_header,
    get_access_mode,
)

import authlib.integrations.base_client.errors as base_client_errors
from werkzeug.middleware.proxy_fix import ProxyFix

import logging


ACCESS_MODE_AUTHENTICATED = "authenticated"
logger = logging.getLogger(__name__)

# Start a Flask application and set its secret
app = Flask(__name__)
app.config.update({"SECRET_KEY": os.getenv("FLASK_SECRET_KEY", os.urandom(32).hex())})

try:
    secrets = load_client_secrets()
except (FileNotFoundError, json.JSONDecodeError) as exc:
    logger.warning("Could not load client secrets (%s). Auth unavailable.", exc)
    
if not isinstance(app.wsgi_app, ProxyFix):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

scopes = ["ogdc:admin"]
auth_client = AuthFactory.create_client("flask", secrets, scopes)

auth_client.init_app(app)

# attach to app context so Flask routes can access it later
app.extensions['dataone_auth'] = auth_client
logger.info("OAuth client initialised.")


def require_scope(required_scope: str, methods=None):
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            mode = get_access_mode()
            
            # In read_only or open mode, skip auth entirely
            if mode != ACCESS_MODE_AUTHENTICATED:
                logger.warning("Access mode '%s': skipping scope validation", mode)
                # Store None in g for consistency
                g.token_claims = None
                return f(*args, **kwargs)
            
            # If methods are specified, only enforce auth for those methods
            if methods is not None and request.method not in methods:
                # No auth required for this method; store None as claims
                g.token_claims = None
                return f(*args, **kwargs)
            
            auth_adapter = current_app.extensions['dataone_auth']

            try:
                # Framework specific: Extract the token
                auth_header = request.headers.get("Authorization", "")
                token = extract_token_from_header(auth_header)
                claims = auth_adapter.validate_and_extract_claims(
                    token_str=token, 
                    required_scope=required_scope
                )
                return f(*args, **kwargs, claims=claims)
            except Exception as e:
                return auth_adapter.error_handler(e)

        return decorated
    return decorator


@app.route("/profile", methods=["GET"])
@require_scope("ogdc:admin")
def profile(claims):
    """Protected resource endpoint that requires 'profile' scope."""
    return (
        jsonify(
            {
                "message": f"Authorization succeeded, {claims.get('name', 'User')}",
                "claims": {
                    "sub": claims.get("sub"),
                    "iss": claims.get("iss"),
                    "aud": claims.get("aud"),
                    "azp": claims.get("azp"),
                    "exp": claims.get("exp"),
                    "iat": claims.get("iat"),
                    "nbf": claims.get("nbf"),
                    "jti": claims.get("jti"),
                    "scope": claims.get("scope"),
                    "name": claims.get("name"),
                    "email": claims.get("email"),
                    "email_verified": claims.get("email_verified"),
                    "preferred_username": claims.get("preferred_username"),
                    "given_name": claims.get("given_name"),
                    "family_name": claims.get("family_name"),
                },
            }
        ),
        200,
    )


@app.route("/login", methods=["GET"])
def login():
    """Initiate the OIDC login flow.

    Sends the user to the provider's login page. After successful
    authentication the provider redirects back to the ``/authorize``
    callback.

    Args:
        (None)

    Returns:
        302 redirect to the provider's authorization endpoint.
        401/500 JSON error response if login fails.
        403 JSON response if authentication is disabled for the current access mode.

    """
    auth_adapter = current_app.extensions['dataone_auth']
    oidc_client = auth_adapter.dataone_oidc # maybe get this dynamically
    try:
        return oidc_client.authorize_redirect(url_for("authorize", _external=True))
    except Exception as exc:
        logger.warning("OIDC authorize_redirect error: %s", exc)
        return auth_adapter.error_handler(exc)



@app.route("/authorize", methods=["GET"])
def authorize():
    """OIDC authorization callback endpoint.

    Keycloak redirects here after a successful login with a short-lived
    authorization code. This endpoint exchanges that code for an access
    token, stores the token and returns it to the caller.

    Returns:
        200 JSON with ``token`` on success.
        401 JSON with error details on failure.
        403 JSON response if authentication is disabled for the current access mode.
    """
    auth_adapter = current_app.extensions.get('dataone_auth')
    oidc_client = auth_adapter.dataone_oidc

    try:
        token = oidc_client.authorize_access_token()
    except (base_client_errors.OAuthError, RequestException) as exc:
        logger.debug("OIDC token exchange error: %s", exc)
        return auth_adapter.error_handler(exc)

    return auth_adapter.token_response(token = token)


@app.route("/refresh", methods=["POST"])
def refresh_token():
    """Re-validate the user session and return a new access token using the refresh token.

    When an access token expires, the client can call this endpoint with the refresh token 
    to obtain a new access token without requiring the user to log in again. The client 
    can also pass the desired scopes for the new access token, which must be a subset 
    of the original scopes granted to the refresh token.

    Parameters (in JSON body):
    - ``refresh_token`` (string, required): The refresh token issued by the OIDC provider.
    - ``scope`` (string, optional): Space-separated list of scopes to request for the new access token. If omitted, the new access token will have the same scopes as the original token.

    Returns:
    200 JSON with new ``access_token`` and ``refresh_token`` on success.
    400 JSON if the request is missing required parameters.
    401 JSON if the refresh token is invalid, expired, or if client authentication fails.
    500 JSON for unexpected server errors.
    """

    auth_adapter = current_app.extensions.get('dataone_auth')

    # Get the refresh token and desired scopes from the JSON body
    data = request.get_json(silent=True)

    user_refresh_token = data.get("refresh_token")

    requested_scope = data.get("scope")

    # Use Authlib to exchange the refresh token for a new access token
    try:
        oidc_client = auth_adapter.dataone_oidc # maybe get this dynamically
        if not requested_scope:
            # If no scope is provided, omit the scope parameter to get the same scopes as the original token
            new_tokens = oidc_client.fetch_access_token(
                grant_type="refresh_token",
                refresh_token=user_refresh_token,
            )
            return auth_adapter.token_response(new_tokens, message="Authorization successful")
        else:
            new_tokens = oidc_client.fetch_access_token(
                grant_type="refresh_token",
                refresh_token=user_refresh_token,
                scope=requested_scope,
            )
            return auth_adapter.token_response(new_tokens, message="Authorization successful")

    except Exception as exc:
        return auth_adapter.error_handler(exc)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int("4000"), debug=True)
