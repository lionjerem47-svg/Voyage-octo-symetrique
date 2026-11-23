import os, sqlite3, secrets, hashlib
from flask import Flask, request, jsonify, g

app = Flask(__name__)
DB = os.environ.get("DB_PATH", "saas.db")

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close(e=None):
    d = g.pop("db", None)
    if d:
        d.close()

def init():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pw TEXT, token TEXT, plan TEXT DEFAULT 'free');
    CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, done INTEGER DEFAULT 0);
    """)
    c.commit()
    c.close()

init()

def hp(p):
    return hashlib.sha256(p.encode()).hexdigest()

def auth():
    t = request.headers.get("Authorization", "").replace("Bearer ", "")
    return db().execute("SELECT * FROM users WHERE token=?", (t,)).fetchone()

@app.get("/")
def home():
    return jsonify(name="TaskFlow SaaS", status="ok")

@app.post("/signup")
def signup():
    d = request.json
    tok = secrets.token_hex(16)
    try:
        db().execute("INSERT INTO users(email,pw,token) VALUES(?,?,?)", (d["email"], hp(d["password"]), tok))
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="email deja utilise"), 409
    return jsonify(token=tok, plan="free")

@app.post("/login")
def login():
    d = request.json
    u = db().execute("SELECT * FROM users WHERE email=? AND pw=?", (d["email"], hp(d["password"]))).fetchone()
    if not u:
        return jsonify(error="identifiants invalides"), 401
    return jsonify(token=u["token"], plan=u["plan"])

@app.post("/tasks")
def add_task():
    u = auth()
    if not u:
        return jsonify(error="non autorise"), 401
    n = db().execute("SELECT COUNT(*) c FROM tasks WHERE user_id=?", (u["id"],)).fetchone()["c"]
    if u["plan"] == "free" and n >= 5:
        return jsonify(error="limite du plan gratuit atteinte, passez en pro"), 402
    cur = db().execute("INSERT INTO tasks(user_id,title) VALUES(?,?)", (u["id"], request.json["title"]))
    db().commit()
    return jsonify(id=cur.lastrowid, title=request.json["title"], done=False)

@app.get("/tasks")
def list_tasks():
    u = auth()
    if not u:
        return jsonify(error="non autorise"), 401
    rows = db().execute("SELECT id,title,done FROM tasks WHERE user_id=?", (u["id"],)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.post("/tasks/<int:i>/done")
def done(i):
    u = auth()
    if not u:
        return jsonify(error="non autorise"), 401
    db().execute("UPDATE tasks SET done=1 WHERE id=? AND user_id=?", (i, u["id"]))
    db().commit()
    return jsonify(ok=True)

@app.post("/upgrade")
def upgrade():
    u = auth()
    if not u:
        return jsonify(error="non autorise"), 401
    db().execute("UPDATE users SET plan='pro' WHERE id=?", (u["id"],))
    db().commit()
    return jsonify(plan="pro")

if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 5055)))j
