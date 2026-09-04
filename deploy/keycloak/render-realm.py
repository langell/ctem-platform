"""Render the committed dev realm for a real origin.

The dev realm only trusts localhost redirect URIs and ships demo secrets.
This runs in a one-shot container before Keycloak starts and writes the
patched realm to the import volume. Keycloak imports it on first boot only;
later edits belong in the admin console (or wipe the keycloak database).
"""
import json
import os
import sys

src, dst = sys.argv[1], sys.argv[2]
origin = os.environ["CTEM_ORIGIN"].rstrip("/")
api_secret = os.environ["OIDC_API_CLIENT_SECRET"]
demo_password = os.environ["DEMO_PASSWORD"]

with open(src) as f:
    realm = json.load(f)

realm["sslRequired"] = "external"

for client in realm.get("clients", []):
    if client["clientId"] == "ctem-web":
        client["redirectUris"] = [f"{origin}/login/callback"]
        client["webOrigins"] = [origin]
    elif client["clientId"] == "ctem-api":
        client["secret"] = api_secret

for user in realm.get("users", []):
    for cred in user.get("credentials", []):
        if cred.get("type", "password") == "password":
            cred["value"] = demo_password

os.makedirs(os.path.dirname(dst), exist_ok=True)
with open(dst, "w") as f:
    json.dump(realm, f, indent=2)
print(f"rendered realm for {origin} -> {dst}")
