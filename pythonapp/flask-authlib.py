"""
A simple Flask application demonstrating OpenID Connect (OIDC) authentication
using the authlib library against a keycloak server. The application includes
only routes for accessing protected resources using only a token.

Call with: curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:4000/profile
"""

import json
import functools
import os
import requests

from flask import Flask
from flask import jsonify
from flask import request
from flask import session
from flask import redirect
from flask import url_for
from authlib.integrations.flask_client import OAuth
from authlib.jose import jwt
from authlib.jose import JsonWebKey
from authlib.jose.errors import InvalidTokenError
from werkzeug.middleware.proxy_fix import ProxyFix


def load_client_secrets(filepath="./client_secrets.json"):
    """Load and parse the client secrets JSON file.

    Args:
        filepath: Path to the client_secrets.json file

    Returns:
        dict: Parsed JSON content from the file

    Raises:
        FileNotFoundError: If the secrets file does not exist
        json.JSONDecodeError: If the file is not valid JSON
    """
    with open(filepath, "r") as f:
        return json.load(f)


# Start a Flask application and set its secret
app = Flask(__name__)
app.config.update({"SECRET_KEY": os.getenv("FLASK_SECRET_KEY", os.urandom(32).hex())})

# Tell flask we are behind a proxy
# x_proto=1 tells Flask to trust the X-Forwarded-Proto header
# x_host=1 tells Flask to trust the X-Forwarded-Host header
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure your OIDC Provider (e.g., Keycloak)
oauth = OAuth(app)
secrets = load_client_secrets()
oauth.register(
    name="dataone_oidc",
    client_id=secrets.get("client_id"),
    client_secret=secrets.get("client_secret"),
    server_metadata_url=secrets.get("server_metadata_url"),
    client_kwargs={"scope": secrets.get("scope_request")},
)


# Fetch and cache JWKS keys from the OIDC provider's jwks_uri
@functools.lru_cache(maxsize=1)
def get_jwks_keys():
    """Fetch and cache JWKS keys from the OIDC provider's jwks_uri."""
    # Get the jwks_uri from server metadata
    metadata = oauth.dataone_oidc.load_server_metadata()
    jwks_uri = metadata.get("jwks_uri")

    if not jwks_uri:
        raise ValueError("OIDC provider metadata does not contain jwks_uri")

    # Fetch JWKS from the provider
    response = requests.get(jwks_uri)
    response.raise_for_status()
    jwks_data = response.json()

    # Convert JWKS to JsonWebKey set for Authlib
    return JsonWebKey.import_key_set(jwks_data)


# Scope-based resource protection decorator
def require_scope(required_scope):
    """Decorator that protects endpoints by verifying OAuth 2.0 token scope."""

    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):

            # Extract token from Authorization header
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return (
                    jsonify({"error": "Missing or invalid Authorization header"}),
                    401,
                )

            token_str = auth_header[7:]  # Remove 'Bearer ' prefix

            try:
                # Fetch JWKS signing keys from the OIDC provider's well-known endpoint
                jwks = get_jwks_keys()

                # Find the issuer from the server metadata
                issuer = oauth.dataone_oidc.load_server_metadata().get("issuer")
                metadata = oauth.dataone_oidc.load_server_metadata()
                issuer = metadata.get("issuer")

                # Decode and validate the JWT token using the signing keys
                claims = jwt.decode(
                    token_str,
                    jwks,
                    claims_options={
                        "iss": {
                            "essential": True,
                            "value": issuer,
                        },
                        "azp": {"essential": True, "value": secrets.get("client_id")},
                    },
                )
                claims.validate()  # This checks exp, iat, iss, and aud

                # Check for required scope
                token_scope = claims.get("scope", "").split()
                if required_scope not in token_scope:
                    return (
                        jsonify(
                            {
                                "error": f"Insufficient scope. Required: {required_scope}",
                                "available_scopes": token_scope,
                            }
                        ),
                        403,
                    )

                # Pass claims to the protected function
                return f(claims, *args, **kwargs)
            except InvalidTokenError as e:
                return (
                    jsonify({"error": "Token validation failed", "details": str(e)}),
                    401,
                )
            except ValueError as e:
                # Raised by get_jwks_keys() if jwks_uri is missing
                return (
                    jsonify(
                        {
                            "error": "OIDC provider configuration, no jwks_uri key found",
                            "details": str(e),
                        }
                    ),
                    500,
                )
            except requests.RequestException as e:
                # Network or HTTP errors when fetching JWKS
                return (
                    jsonify(
                        {
                            "error": "Failed to fetch OIDC provider keys",
                            "details": str(e),
                        }
                    ),
                    502,
                )
            except (KeyError, TypeError) as e:
                # Unexpected data structure in token claims
                return (
                    jsonify({"error": "Invalid token structure", "details": str(e)}),
                    401,
                )

        return decorated_function

    return decorator


@app.route("/profile", methods=["GET"])
@require_scope("vegbank:contributor")
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
    """Initiates OpenID Connect login flow."""
    redirect_uri = url_for("authorize", _external=True)
    return oauth.dataone_oidc.authorize_redirect(redirect_uri)


@app.route("/authorize", methods=["GET"])
def authorize():
    """Callback endpoint for OIDC authorization redirect."""
    try:
        token = oauth.dataone_oidc.authorize_access_token()
        session["token"] = token
        session["userinfo"] = token.get("userinfo", {})
        return redirect(url_for("dashboard"))
    except Exception as e:
        return jsonify({"error": "Authorization failed", "details": str(e)}), 401


@app.route("/dashboard", methods=["GET"])
def dashboard():
    """User dashboard showing authenticated user info."""
    userinfo = session.get("userinfo")
    if not userinfo:
        return redirect(url_for("login"))

    return (
        jsonify(
            {
                "message": f"Welcome, {userinfo.get('name', 'User')}!",
                "user": {
                    "name": userinfo.get("name"),
                    "email": userinfo.get("email"),
                    "sub": userinfo.get("sub"),
                },
                "token": session.get("token"),
            }
        ),
        200,
    )


@app.route("/logout", methods=["GET"])
def logout():
    """Clears the user session."""
    session.clear()
    # Optionally redirect to OIDC provider's logout endpoint
    return jsonify({"message": "Logged out successfully"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int("4000"), debug=True)
