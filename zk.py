import secrets
import json
import hashlib

# Ler parâmetros do ficheiro JSON
def load_params():
    with open("zk_params.json", "r") as f:
        params = json.load(f)
        return int(params["p"]), int(params["q"]), int(params["g"])

p, q, g = load_params()

def to_secret_int(secret: str) -> int:
    # Transforma o segredo (string) num inteiro via SHA-256
    return int(hashlib.sha256(secret.encode()).hexdigest(), 16) % q

def generate_keys(secret: str):
    return pow(g, to_secret_int(secret), p)

def generate_proof(secret: str):
    v = secrets.randbelow(q)
    r = pow(g, v, p)
    return v, r

def compute_response(v: int, c: int, secret: str):
    x = to_secret_int(secret)
    return (v + c * x) % q

def verify_proof(y: int, r: int, c: int, s: int):
    lhs = pow(g, s, p)
    rhs = (r * pow(y, c, p)) % p
    return lhs == rhs
