# OIDC Example

This is a simple library illustrating a flask app with OIDC authentication and 
REST-based resource API protections based on a requested `scope` value.

The library has two examples, one based on Authlib (flask-authlib.py), which is more complete and functional than the other (app.py) which is based on the older flask_oidc library.

The flask-authlib.py starts a Flask server that exposes the following endpoints:

- `/login`: Initiate a redirect to an OIDC auth endpoint to login
- `/authorize`: The callback endpoint for OAuth2 code exchange
- `/dashboard`: Print out details of auth tokens retireved (normally these would be treated securely)
- `/logout`: Invalidate the session -- I think this is not fully working due to a Keycloak config issue
- `/profile`: A REST endpoint that requires a valid access Bearer token and a valid `vegbank:contributor` scope 

## Configuration

All OIDC connect endpoint details, the client ID, and secret must be in the file `client_secrets.json` before
the app is started.

## Call a rest endpoint that is gated by a scoped access token

This is an exanple of calling a token-protected REST endpoint. This endpoint requires a Bearer token, but could be written allow either a Bearer token or a valid OIDC session like the `/dashboard` method does.

```bash
❯ curl -H "Authorization: Bearer ${TOKEN}" "https://api.test.dataone.org/profile"
```

```json
{
  "claims": {
    "aud": null,
    "azp": "ogdc",
    "email": "jones@nceas.ucsb.edu",
    "email_verified": false,
    "exp": 1769671728,
    "family_name": "Jones",
    "given_name": "Matthew",
    "iat": 1769668128,
    "iss": "https://auth.test.dataone.org/realms/dataone",
    "jti": "onrtrt:ad6c26b2-5f67-ce18-7748-cbcb349fa535",
    "name": "Matthew Jones",
    "nbf": null,
    "preferred_username": "metamattj",
    "scope": "openid profile email vegbank:contributor vegbank:admin",
    "sub": "fc394b32-9ff7-485d-82f3-7db6824c8cb5"
  },
  "message": "Authorization succeeded, Matthew Jones"
}
```

## Exchange a refresh token to get a new ACCESS token and REFRESH token

Access tokens expire frequently, but can be exchnaged using a refresh token from the provider. Refresh tokens generally last much longer in OIDC environments, and allow continued access without logging back in, but only if the client software uses the refresh token to get a new access token. When the new access token is retirieved, a new refresh token is also sent, which should be saved -- typically refresh tokens can only be used once.

```bash
❯ curl -s -L -X POST 'https://auth.test.dataone.org/realms/dataone/protocol/openid-connect/token' \
-H "Content-Type: application/x-www-form-urlencoded" \
--data-urlencode "client_id=ogdc" \
--data-urlencode "client_secret=${CLIENT_SECRET}" \
--data-urlencode "grant_type=refresh_token" \
--data-urlencode "refresh_token=${REFRESH}"
```
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3aUFQTnZuc1I1RS1WLTVuaG5UclRvcTUyeTBnT0gwWXd2dmx3VW9BVWJVIn0.eyJleHAiOjE3Njk2NzE3MjgsImlhdCI6MTc2OTY2ODEyOCwiYXV0aF90aW1lIjoxNzY5NjYxNzA0LCJqdGkiOiJvbnJ0cnQ6YWQ2YzI2YjItNWY2Ny1jZTE4LTc3NDgtY2JjYjM0OWZhNTM1IiwiaXNzIjoiaHR0cHM6Ly9hdXRoLnRlc3QuZGF0YW9uZS5vcmcvcmVhbG1zL2RhdGFvbmUiLCJzdWIiOiJmYzM5NGIzMi05ZmY3LTQ4NWQtODJmMy03ZGI2ODI0YzhjYjUiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJvZ2RjIiwic2lkIjoiLTN1Rm5SWjZKR0cxaWxYSmZYbjNQTHZuIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2FwaS50ZXN0LmRhdGFvbmUub3JnIl0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwgdmVnYmFuazpjb250cmlidXRvciB2ZWdiYW5rOmFkbWluIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJ2ZXJpZmllZCI6dHJ1ZSwibmFtZSI6Ik1hdHRoZXcgSm9uZXMiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJtZXRhbWF0dGoiLCJnaXZlbl9uYW1lIjoiTWF0dGhldyIsImZhbWlseV9uYW1lIjoiSm9uZXMiLCJlbWFpbCI6ImpvbmVzQG5jZWFzLnVjc2IuZWR1In0.guUa1eTiTpcPkQqIUNHy5tcrPoy5PI4QIjyd0ZKsPMCb3u19OKxlMvFX2nOfncX2_O7KK-u7f_bNGo9z0ftr0FCSWC9ZEvDtRyHdK-60_3Pizvgq8SPsRP9363-t39RjClo6t0Dd5N2P6L2Blcylhxes_cmS2fT8xQwZIBmvUCKXoafBCvdbKHU5hLUCxOEbrjE1ZBWejN2dlgglA1dgU-HOZxHu-2m76GWWui1nW7mOHNOkgFLxFjJ7HLNuxleh_T1lciYBKTjXe8MfsR1hABm1u15ABVfE96VZkMCWxZMJanffxUaEa73rEvPSBhgxCmuB_6kNHu0FhdHrWdP4uA",
  "expires_in": 3600,
  "refresh_expires_in": 64800,
  "refresh_token": "eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4YzM5ZTU5Mi1hMzBkLTQ5MTAtYTM5ZC1kODQxOWYzMTU4ZTEifQ.eyJleHAiOjE3Njk3MzI5MjgsImlhdCI6MTc2OTY2ODEyOCwianRpIjoiY2Y4MWVhNTgtZjViZC1mNWUzLTJhMmEtMDE5YTA2NjU3MTM1IiwiaXNzIjoiaHR0cHM6Ly9hdXRoLnRlc3QuZGF0YW9uZS5vcmcvcmVhbG1zL2RhdGFvbmUiLCJhdWQiOiJodHRwczovL2F1dGgudGVzdC5kYXRhb25lLm9yZy9yZWFsbXMvZGF0YW9uZSIsInN1YiI6ImZjMzk0YjMyLTlmZjctNDg1ZC04MmYzLTdkYjY4MjRjOGNiNSIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJvZ2RjIiwic2lkIjoiLTN1Rm5SWjZKR0cxaWxYSmZYbjNQTHZuIiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCB2ZWdiYW5rOmNvbnRyaWJ1dG9yIHdlYi1vcmlnaW5zIHZlZ2Jhbms6YWRtaW4gYWNyIGJhc2ljIiwicmV1c2VfaWQiOiIxMzM0OTA4OC01MzQ3LTQzMGQtYjc1OS05YzNlZmQ4NmE3NjkifQ.vsml3DUiDyWVEoic6PpXZ9adrngsrVwI6EZMe-1IeXpuLJ65x1E3op2kZm36k0REiwZ2_KcyJMRgJ8GD5BtyBw",
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3aUFQTnZuc1I1RS1WLTVuaG5UclRvcTUyeTBnT0gwWXd2dmx3VW9BVWJVIn0.eyJleHAiOjE3Njk2NzE3MjgsImlhdCI6MTc2OTY2ODEyOCwiYXV0aF90aW1lIjoxNzY5NjYxNzA0LCJqdGkiOiIyMGFkN2NkYS1mZDZmLTZjZWMtYzMyOC03ZjY0YjgzZmEyYWMiLCJpc3MiOiJodHRwczovL2F1dGgudGVzdC5kYXRhb25lLm9yZy9yZWFsbXMvZGF0YW9uZSIsImF1ZCI6Im9nZGMiLCJzdWIiOiJmYzM5NGIzMi05ZmY3LTQ4NWQtODJmMy03ZGI2ODI0YzhjYjUiLCJ0eXAiOiJJRCIsImF6cCI6Im9nZGMiLCJzaWQiOiItM3VGblJaNkpHRzFpbFhKZlhuM1BMdm4iLCJhdF9oYXNoIjoibmVwR0JRRWZ5aUNyY0tmS0s5RDR2QSIsImFjciI6IjEiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiTWF0dGhldyBKb25lcyIsInByZWZlcnJlZF91c2VybmFtZSI6Im1ldGFtYXR0aiIsImdpdmVuX25hbWUiOiJNYXR0aGV3IiwiZmFtaWx5X25hbWUiOiJKb25lcyIsImVtYWlsIjoiam9uZXNAbmNlYXMudWNzYi5lZHUifQ.r6oGAju6C7mibKlLW9ISdyfDDJU7i5wLwV3vKTVh3SpQWfT6xQP7wBAF_0jP90jrjSW-1fBwp4gllMkq_wasd58Q8j3Jvc4tzgC1-0zOtu1O-W8BEgG-LBwhdmG2qdskTNw4J51mcq3tSiAyAgbjfG51WamOxZCbfXTeWvw8AOXub2M-ete1fwzylBQBS_-J2rIuJP1BdOlL45oweUkmthHzpLNlvAKKtWWfxe3pJ65NigBAo_pYg18Ja4uX3Ev1wsHEIX9bD13uk4SjW_WyHSwqjWlZRj1D1W59F8Fxkb3mksF8KNhTwogrUSWjMJpEGRF5iVjq9_EyxgtFDtQCog",
  "not-before-policy": 0,
  "session_state": "-3uFnRZ6JGG1ilXJfXn3PLvn",
  "scope": "openid profile email vegbank:contributor vegbank:admin"
}
```
