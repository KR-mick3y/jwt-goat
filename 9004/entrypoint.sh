#!/bin/sh
set -eu

python - <<'PY'
import hashlib
import secrets

# Runtime flag
flag_digest = hashlib.md5(secrets.token_bytes(32)).hexdigest()
with open("/app/flag.txt", "w", encoding="utf-8") as f:
    f.write(f"FLAG{{{flag_digest}}}")

# Runtime JWT secret: exactly 6 decimal digits
secret = f"{secrets.randbelow(1_000_000):06d}"
with open("/run/jwt_secret", "w", encoding="utf-8") as f:
    f.write(secret)
PY

exec python app.py
