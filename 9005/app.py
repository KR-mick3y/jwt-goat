
from flask import Flask, request, jsonify, Response
import base64
import json
import time
import urllib.request
import jwt

from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

KID = "lab-rsa-1"

# Generated fresh whenever the container starts.
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()


def read_flag():
    with open("/app/flag.txt", "r", encoding="utf-8") as f:
        return f.read().strip()


def b64u_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


numbers = public_key.public_numbers()

JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KID,
            "n": b64u_uint(numbers.n),
            "e": b64u_uint(numbers.e)
        }
    ]
}


def jwk_to_public_key(jwk):
    n = int.from_bytes(b64u_decode(jwk["n"]), "big")
    e = int.from_bytes(b64u_decode(jwk["e"]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


@app.get("/")
def root():
    return jsonify({
        "lab": "JWT jku SSRF",
        "flag_endpoint": "/flag",
        "endpoints": {
            "GET /login": {},
            "GET /admin": "Authorization: Bearer <token>",
            "GET /.well-known/openid-configuration": {}
        }
    })


@app.get("/.well-known/openid-configuration")
def oidc():
    return jsonify({
        "issuer": "http://127.0.0.1:9005",
        "jwks_uri": "http://127.0.0.1:9005/oauth2/v1/keys",
        "id_token_signing_alg_values_supported": ["RS256"]
    })


@app.get("/oauth2/v1/keys")
def jwks():
    return jsonify(JWKS)


@app.get("/login")
def login():
    token = jwt.encode(
        {
            "name": "anonymous",
            "role": "anonymous",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        },
        private_key,
        algorithm="RS256",
        headers={
            "kid": KID,
            "typ": "JWT",
            "jku": "http://127.0.0.1:9005/oauth2/v1/keys"
        }
    )
    return jsonify({"token": token})


@app.get("/flag")
def flag():
    # Direct requests through Docker arrive from the bridge, not loopback.
    # Only a request originating from the container's own loopback is allowed.
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({"error": "localhost only"}), 403

    return Response(read_flag(), mimetype="text/plain")


@app.get("/admin")
def admin():
    try:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing bearer token"}), 401

        token = auth[7:]

        # Intentionally read attacker-controlled header values before
        # signature verification.
        header = jwt.get_unverified_header(token)
        jku = header.get("jku")
        kid = header.get("kid")

        if not jku:
            return jsonify({"error": "missing jku"}), 400

        # Intentionally vulnerable SSRF:
        # the jku URL is trusted and fetched without an allowlist.
        with urllib.request.urlopen(jku, timeout=3) as response:
            upstream_body = response.read().decode("utf-8", errors="replace")

        # Normal path: treat the fetched body as JWKS and verify RS256.
        # Lab path: if jku points to /flag, the body is not JSON; expose it
        # so students can observe the SSRF result in a black-box exercise.
        try:
            jwks_data = json.loads(upstream_body)
        except json.JSONDecodeError:
            return jsonify({
                "error": "invalid JWKS response",
                "upstream_body": upstream_body
            }), 400

        selected = None
        for item in jwks_data.get("keys", []):
            if item.get("kid") == kid:
                selected = item
                break

        if selected is None:
            return jsonify({"error": "kid not found"}), 401

        verify_key = jwk_to_public_key(selected)

        payload = jwt.decode(
            token,
            verify_key,
            algorithms=["RS256"]
        )

        if payload.get("role") != "admin":
            return jsonify({"error": "forbidden"}), 403

        return jsonify({"flag": read_flag()})

    except Exception as e:
        return jsonify({
            "error": "request failed",
            "detail": str(e)
        }), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9005, threaded=True)
