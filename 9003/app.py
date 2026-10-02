
from flask import Flask, request, jsonify
import base64
import hashlib
import hmac
import json
import time
import jwt

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

KID = "lab-rsa-1"

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

PUBLIC_PEM = public_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)

def b64u_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

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

def read_flag():
    with open("/app/flag.txt", "r", encoding="utf-8") as f:
        return f.read().strip()

def b64u_decode(segment: str) -> bytes:
    segment += "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment)

@app.get("/")
def root():
    return jsonify({
        "lab": "RS256 to HS256 algorithm confusion",
        "endpoints": {
            "GET /login": {},
            "GET /admin": {
                "header": "Authorization: Bearer <token>"
            },
            "GET /.well-known/openid-configuration": {},
            "GET /oauth2/v1/keys": {}
        },
        "resources": {
            "discovery": "/.well-known/openid-configuration"
        }
    })

@app.get("/.well-known/openid-configuration")
def oidc():
    return jsonify({
        "issuer": "http://127.0.0.1:9003",
        "jwks_uri": "http://127.0.0.1:9003/oauth2/v1/keys",
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
            "typ": "JWT"
        }
    )
    return jsonify({"token": token})

def verify_confused(token: str):
    header = jwt.get_unverified_header(token)

    if header.get("kid") != KID:
        raise ValueError("unknown kid")

    alg = header.get("alg")

    if alg == "RS256":
        return jwt.decode(
            token,
            public_key,
            algorithms=["RS256"]
        )

    if alg == "HS256":
        # Intentionally vulnerable:
        # the RSA public key PEM bytes are incorrectly reused as an HMAC secret.
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("malformed token")

        signing_input = (parts[0] + "." + parts[1]).encode()
        supplied_signature = b64u_decode(parts[2])

        expected_signature = hmac.new(
            PUBLIC_PEM,
            signing_input,
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(expected_signature, supplied_signature):
            raise ValueError("signature verification failed")

        payload = json.loads(b64u_decode(parts[1]))

        exp = payload.get("exp")
        if exp is not None and int(exp) < int(time.time()):
            raise ValueError("token expired")

        return payload

    raise ValueError("unsupported algorithm")

@app.get("/admin")
def admin():
    try:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing bearer token"}), 401

        token = auth[7:]
        payload = verify_confused(token)

        if payload.get("role") != "admin":
            return jsonify({"error": "forbidden"}), 403

        return jsonify({"flag": read_flag()})

    except Exception as e:
        return jsonify({
            "error": "invalid token",
            "detail": str(e)
        }), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
