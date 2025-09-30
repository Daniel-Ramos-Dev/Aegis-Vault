#!/usr/bin/env python3
import sqlite3
import sys

DB = "data.db"

def run(sql, params=()):
    conn = sqlite3.connect(DB, timeout=30)
    try:
        conn.execute("BEGIN")
        conn.execute(sql, params)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print("Erro:", e)
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso:")
        print("  python manage_db.py set-pass <user> <nova_senha>")
        print("  python manage_db.py clear-ip <user>")
        print("  python manage_db.py set-admin <user>")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "set-pass" and len(sys.argv) == 4:
        _, _, user, newpass = sys.argv
        run("UPDATE users SET password=? WHERE username=?", (newpass, user))
        print(f"Senha do usuário {user} alterada.")
    elif cmd == "clear-ip" and len(sys.argv) == 3:
        _, _, user = sys.argv
        run("UPDATE users SET ip=NULL WHERE username=?", (user,))
        print(f"IP do usuário {user} limpo.")
    elif cmd == "set-admin" and len(sys.argv) == 3:
        _, _, user = sys.argv
        run("UPDATE users SET isAdmin=1 WHERE username=?", (user,))
        print(f"Usuário {user} agora é admin.")
    else:
        print("Comando inválido ou parâmetros faltando.")
