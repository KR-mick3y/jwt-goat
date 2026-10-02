
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
        "lab": "JWT alg:none",
        "endpoints": {
            "GET /login": {},
            "GET /admin": "Authorization: Bearer <token>"
        }
    })

@app.get("/login")
def login(): return jsonify({"token":jwt.encode({"name":"anonymous","role":"anonymous"},read_secret(),algorithm="HS256")})
@app.get("/admin")
def admin():
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        header = jwt.get_unverified_header(token)

        if header.get("alg") == "none":
            payload = jwt.decode(
                token,
                options={"verify_signature": False},
                algorithms=["none"]
            )
        else:
            payload = jwt.decode(
                token,
                read_secret(),
                algorithms=["HS256"]
            )

        if payload.get("role") == "admin":
            return {"flag": read_flag()}

    except Exception as e:
        return {"error": "invalid token", "detail": str(e)}, 401

    return {"error": "forbidden"}, 403

app.run(host="0.0.0.0")
