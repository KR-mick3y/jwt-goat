#!/bin/sh
set -eu

python - <<'PY'
import hashlib
import secrets
import string

# Runtime flag
flag_digest = hashlib.md5(secrets.token_bytes(32)).hexdigest()
with open("/app/flag.txt", "w", encoding="utf-8") as f:
    f.write(f"FLAG{{{flag_digest}}}")

# Runtime JWT secret: 20 alphanumeric chars with at least one letter and one digit
alphabet = string.ascii_letters + string.digits
while True:
    secret = "".join(secrets.choice(alphabet) for _ in range(20))
    if any(c.isalpha() for c in secret) and any(c.isdigit() for c in secret):
        break

with open("/run/jwt_secret", "w", encoding="utf-8") as f:
    f.write(secret)
PY

exec python app.py
