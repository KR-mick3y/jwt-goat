#!/bin/sh
set -eu

python - <<'PY'
import hashlib
import secrets

random_value = secrets.token_bytes(32)
digest = hashlib.md5(random_value).hexdigest()

with open("/app/flag.txt", "w", encoding="utf-8") as f:
    f.write(f"FLAG{{{digest}}}")
PY

exec python app.py
