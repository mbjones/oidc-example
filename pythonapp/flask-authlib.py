"""
A simple Flask application demonstrating OpenID Connect (OIDC) authentication
using the authlib library against a keycloak server. The application includes
only routes for accessing protected resources using only a token.

Call with: curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:4000/profile
"""

import json
import logging
import os

from flask import Flask, jsonify, request, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from dataone.auth import AuthFactory, load_client_secrets


# --- Constants & Logging ---
ACCESS_MODE_AUTHENTICATED = "authenticated"
scopes = ["ogdc:admin"]
logger = logging.getLogger(__name__)


# --- App Initialization ---
app = Flask(__name__)
app.config.update({"SECRET_KEY": os.getenv("FLASK_SECRET_KEY", os.urandom(32).hex())})

if not isinstance(app.wsgi_app, ProxyFix):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# --- Auth Setup ---
try:
    secrets = load_client_secrets()
except (FileNotFoundError, json.JSONDecodeError) as exc:
    logger.warning("Could not load client secrets (%s). Auth unavailable.", exc)
    
auth_client = AuthFactory.create_client("flask", secrets, scopes)
auth_client.init_app(app)

# attach to app context so Flask routes can access it later
app.extensions['dataone_auth'] = auth_client
logger.info("OAuth client initialised.")


# --- Routes ---
@app.route("/login")
def login():
    return auth_client.login(redirect_uri=url_for("authorize", _external=True))

@app.route("/authorize")
def authorize():
    return auth_client.authorize()

@app.route("/refresh", methods=["POST"])
def refresh_token():
    return auth_client.refresh(request_json=request.get_json(silent=True))

@app.route("/profile", methods=["GET"])
@auth_client.require_scope("ogdc:admin")
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

# --- Execution ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int("4000"), debug=True)