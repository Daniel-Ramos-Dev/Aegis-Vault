from flask import Flask, request, session, redirect, url_for, render_template
from flask_session import Session
from cryptography.fernet import Fernet
import psycopg2
import psycopg2.extras
import os

KEY_FILE = "secret.key"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "troque_esta_sementinha_para_producao")
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

DATABASE_URL = os.environ.get("DATABASE_URL")

# ------------------ Funções auxiliares ------------------

def get_db():
    conn = psycopg2.connect(DATABASE_URL, sslmode="require")
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            ip TEXT,
            isAdmin BOOLEAN NOT NULL DEFAULT FALSE
        )
    """)
    conn.commit()
    cur.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]
    if count == 0:
        cur.executemany("INSERT INTO users (username, password, ip, isAdmin) VALUES (%s,%s,%s,%s)", [
            ("Ghost", "Dev-2007", None, True),
            ("Zoca", "917382645", None, True),
            ("daniel", "1234", None, False)
        ])
        conn.commit()
    cur.close()
    conn.close()

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

def is_admin_user(username):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT isAdmin FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    conn.close()
    return bool(row and row["isAdmin"])

# ------------------ Inicialização ------------------

init_db()
fernet = Fernet(load_key())

# ------------------ Rotas ------------------

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    ip = request.remote_addr

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT username, password, ip, isAdmin FROM users WHERE username=%s", (username,))
    row = cur.fetchone()

    if not row or row["password"] != password:
        conn.close()
        return "Usuário ou senha incorretos."

    is_admin = bool(row["isadmin"])
    stored_ip = row["ip"]

    if not is_admin:
        if stored_ip is None:
            cur.execute("UPDATE users SET ip=%s WHERE username=%s", (ip, username))
            conn.commit()
        elif stored_ip != ip:
            conn.close()
            return "Acesso negado: IP não autorizado."

    conn.close()
    session["user"] = username
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("home"))
    return render_template("dashboard.html", is_admin=is_admin_user(session["user"]))

@app.route("/encrypt", methods=["POST"])
def encrypt():
    if "user" not in session:
        return redirect(url_for("home"))
    text = request.form.get("text", "")
    encrypted = fernet.encrypt(text.encode()).decode()
    return render_template("result.html",
                           titulo="Texto Criptografado",
                           conteudo=encrypted,
                           is_admin=is_admin_user(session["user"]))

@app.route("/decrypt", methods=["POST"])
def decrypt():
    if "user" not in session:
        return redirect(url_for("home"))
    text = request.form.get("text", "")
    try:
        decrypted = fernet.decrypt(text.encode()).decode()
        return render_template("result.html",
                               titulo="Texto Descriptografado",
                               conteudo=decrypted,
                               is_admin=is_admin_user(session["user"]))
    except Exception:
        return render_template("result.html",
                               titulo="Erro",
                               conteudo="Texto inválido ou corrompido.",
                               is_admin=is_admin_user(session["user"]))

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))

# ------------------ Admin Console ------------------

@app.route("/admin-console", methods=["GET", "POST"])
def admin_console():
    if "user" not in session:
        return redirect(url_for("home"))
    user = session["user"]
    if not is_admin_user(user):
        return "Acesso negado: rota apenas para administradores."

    query = ""
    results = None
    columns = []
    message = None

    if request.method == "POST":
        action = request.form.get("action")
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        if action == "clear_ip":
            target = request.form.get("target_user")
            if target:
                try:
                    cur.execute("UPDATE users SET ip=NULL WHERE username=%s", (target,))
                    conn.commit()
                    message = f"IP de {target} limpo."
                except Exception as e:
                    message = f"Erro: {e}"
        else:
            query = request.form.get("sql", "").strip()
            if query:
                try:
                    cur.execute(query)
                    if query.lower().startswith("select"):
                        rows = cur.fetchall()
                        columns = rows[0].keys() if rows else []
                        results = [tuple(r) for r in rows]
                    else:
                        conn.commit()
                        message = "Comando executado com sucesso."
                except Exception as e:
                    message = f"Erro ao executar SQL: {e}"

        cur.close()
        conn.close()

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT username, ip, isAdmin FROM users")
    users = cur.fetchall()
    conn.close()

    return render_template("admin_console.html",
                           query=query,
                           results=results,
                           columns=columns,
                           message=message,
                           users=users,
                           is_admin=True)

# ------------------ Run ------------------

if __name__ == "__main__":
    app.run()
