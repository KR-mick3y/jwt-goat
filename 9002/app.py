
from flask import Flask, request, jsonify
import jwt
import sqlite3

app = Flask(__name__)

def read_secret():
    with open("/run/jwt_secret", "r", encoding="utf-8") as f:
        return f.read().strip()

def initdb():
    con = sqlite3.connect("/app/lab.db")

    con.execute("""
        CREATE TABLE IF NOT EXISTS jwt_keys (
            kid TEXT,
            key_name TEXT
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS flags (
            flag TEXT
        )
    """)

    con.execute("DELETE FROM jwt_keys")
    con.execute("DELETE FROM flags")

    con.execute(
        "INSERT INTO jwt_keys VALUES ('default.key', 'default-key')"
    )
    con.execute(
        "INSERT INTO jwt_keys VALUES ('admin.key', 'admin-key')"
    )
    with open("/app/flag.txt", "r", encoding="utf-8") as f:
        runtime_flag = f.read().strip()

    con.execute(
        "INSERT INTO flags VALUES (?)",
        (runtime_flag,)
    )

    con.commit()
    con.close()

initdb()

@app.get("/")
def root():
    return jsonify({
        "lab": "JWT kid SQL injection",
        "target": {
            "database": "SQLite",
            "flag_table": "flags",
            "flag_column": "flag"
        },
        "endpoints": {
            "GET /login": {},
            "GET /admin": "Authorization: Bearer <token>"
        }
    })

@app.get("/login")
def login():
    token = jwt.encode(
        {
            "name": "anonymous",
            "role": "anonymous"
        },
        read_secret(),
        algorithm="HS256",
        headers={"kid": "default.key"}
    )
    return jsonify({"token": token})

@app.get("/admin")
def admin():
    try:
        token = request.headers["Authorization"].replace("Bearer ", "")
        kid = jwt.get_unverified_header(token)["kid"]

        query = f"SELECT key_name FROM jwt_keys WHERE kid='{kid}'"

        con = sqlite3.connect("/app/lab.db")
        row = con.execute(query).fetchone()
        con.close()

        if row is None:
            return jsonify({"result": None}), 404

        return jsonify({"result": row[0]})

    except Exception as e:
        return jsonify({
            "error": "database error",
            "detail": str(e)
        }), 500

app.run(host="0.0.0.0", port=5000)
