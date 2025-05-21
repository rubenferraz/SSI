from flask import Flask, request, jsonify
import sqlite3, os, time, base64, secrets

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes

from utils_crypto import encrypt_aes
from zk import p, q, g, verify_proof
print("SERVER p =", p)  # debug opcional

app = Flask(__name__)
DB_FILE = "db.sqlite3"
users = {}          # token -> user
aes_keys = {}       # token -> (key, iv)
zk_users = {}       # username -> y
zk_sessions = {}    # username -> (r, c)

# RSA para troca segura de chave AES
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                total_scratch INTEGER DEFAULT 0,
                total_wins INTEGER DEFAULT 0,
                last_time REAL DEFAULT 0
            )
        ''')
        conn.commit()

@app.route("/zk_register", methods=["POST"])
def zk_register():
    data = request.json
    username = data["username"]
    y = int(data["y"])

    if username in zk_users:
        return jsonify({"error": "Utilizador já existe (ZKP)"}), 400

    zk_users[username] = y

    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        if not c.fetchone():
            c.execute("INSERT INTO users (username) VALUES (?)", (username,))
            conn.commit()

    return jsonify({"msg": "Utilizador registado com sucesso (ZKP)"})

@app.route("/zk_start", methods=["POST"])
def zk_start():
    data = request.json
    username = data["username"]
    r = int(data["r"])

    if username not in zk_users:
        return jsonify({"error": "Utilizador não existe"}), 404

    c = secrets.randbelow(q)
    c = c % q
    if c ==0:
        c = 1
    zk_sessions[username] = (r, c)
    return jsonify({"c": c})

@app.route("/zk_verify", methods=["POST"])
def zk_verify():
    data = request.json
    username = data["username"]
    s = int(data["s"])

    if username not in zk_sessions:
        return jsonify({"error": "Sessão não iniciada"}), 400

    r, c = zk_sessions[username]
    y = zk_users.get(username)

    # DEBUG COMPLETO
    print("\n🛠 DEBUG ZKP:")
    print(f"username: {username}")
    print(f"y        = {y}")
    print(f"r        = {r}")
    print(f"c        = {c}")
    print(f"s        = {s}")
    lhs = pow(g, s, p)
    rhs = (r * pow(y, c, p)) % p
    print(f"lhs      = {lhs}")
    print(f"rhs      = {rhs}")
    print("✔️ Verifica:", lhs == rhs)

    if lhs == rhs:
        token = base64.b64encode(os.urandom(16)).decode()
        users[token] = {"username": username}
        del zk_sessions[username]
        return jsonify({"msg": "Login ZKP com sucesso", "token": token})
    else:
        return jsonify({"error": "Verificação falhou"}), 401

@app.route("/rsa_pub", methods=["GET"])
def get_rsa_pub():
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode()

@app.route("/aes_key", methods=["POST"])
def receive_aes_key():
    token = request.headers.get("Authorization")
    if token not in users:
        return jsonify({"error": "Não autenticado"}), 401

    data = request.json
    enc_key = base64.b64decode(data["enc_key"])
    enc_iv = base64.b64decode(data["enc_iv"])

    key = private_key.decrypt(
        enc_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None)
    )
    iv = private_key.decrypt(
        enc_iv,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None)
    )

    aes_keys[token] = (key, iv)
    return jsonify({"msg": "Chave AES recebida com sucesso"})

@app.route("/scratch", methods=["GET"])
def scratch():
    token = request.headers.get("Authorization")
    if token not in users:
        return jsonify({"error": "Não autenticado"}), 401

    if token not in aes_keys:
        return jsonify({"error": "Chave AES não enviada"}), 400

    username = users[token]["username"]
    now = time.time()
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT last_time FROM users WHERE username = ?", (username,))
        last = c.fetchone()[0]
        if now - last < 3600:
            return jsonify({"error": "Só podes pedir uma raspadinha por hora"}), 429

        result = "1" if os.urandom(1)[0] % 2 == 0 else "0"
        key, iv = aes_keys[token]
        encrypted = encrypt_aes(result, key, iv)

        c.execute('''
            UPDATE users
            SET total_scratch = total_scratch + 1,
                total_wins = total_wins + ?,
                last_time = ?
            WHERE username = ?
        ''', (int(result), now, username))
        conn.commit()

    return jsonify({"raspadinha": base64.b64encode(encrypted).decode()})

@app.route("/stats", methods=["GET"])
def stats():
    token = request.headers.get("Authorization")
    if token not in users:
        return jsonify({"error": "Não autenticado"}), 401

    username = users[token]["username"]
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT total_scratch, total_wins FROM users WHERE username = ?", (username,))
        row = c.fetchone()

    return jsonify({
        "utilizador": username,
        "total_raspadinhas": row[0],
        "total_premios": row[1]
    })

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
