"""
A simple Flask application demonstrating OpenID Connect (OIDC) authentication
using the authlib library against a keycloak server. The application includes
only routes for accessing protected resources using only a token.

Call with: curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:4000/profile
"""

import json
import functools
import os

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

@app.route("/login")
def login():
    return auth_client.login(redirect_uri=url_for("authorize", _external=True))

@app.route("/authorize")
def authorize():
    return auth_client.authorize()

@app.route("/refresh", methods=["POST"])
def refresh_token():
    return auth_client.refresh(request_json=request.get_json(silent=True))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int("4000"), debug=True)
