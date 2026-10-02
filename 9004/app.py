
from flask import Flask,request,jsonify
import jwt,time,json,base64
app=Flask(__name__)

def read_secret():
    with open("/run/jwt_secret", "r", encoding="utf-8") as f:
        return f.read().strip()

def read_flag():
    with open("/app/flag.txt", "r", encoding="utf-8") as f:
        return f.read().strip()
def info(name,extra=None):
    d={"lab":name,"target":{"flag_location":"/app/flag.txt"},
       "endpoints":{"GET /login":{},
                    "GET /admin":"Authorization: Bearer <token>"}}
    if extra:d["resources"]=extra
    return d

@app.get("/")
def root():
    return jsonify({
        "lab": "Weak HS256 secret crack",
        "secret_info": {
            "format": "6-digit numeric",
            "range": "000000-999999",
            "generated_at": "container start"
        },
        "endpoints": {
            "GET /login": {},
            "GET /admin": "Authorization: Bearer <token>"
        }
    })

@app.get("/login")
def login(): return {"token":jwt.encode({"name":"anonymous","role":"anonymous"},read_secret(),algorithm="HS256")}
@app.get("/admin")
def admin():
    try:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return {"error": "missing bearer token"}, 401

        token = auth[7:]

        payload = jwt.decode(
            token,
            read_secret(),
            algorithms=["HS256"]
        )

        if payload.get("role") != "admin":
            return {"error": "forbidden"}, 403

        return {"flag": read_flag()}

    except Exception as e:
        return {
            "error": "invalid token",
            "detail": str(e)
        }, 401
app.run(host="0.0.0.0")
