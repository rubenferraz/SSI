import requests
import base64
import os
import re

from utils_crypto import decrypt_aes
from zk import generate_keys, generate_proof, compute_response, p

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

# 🛡️ Função para validar a senha
def is_secure_password(password):
    """
    A senha deve ter:
    - Pelo menos 8 caracteres
    - Pelo menos 1 letra maiúscula
    - Pelo menos 1 letra minúscula
    - Pelo menos 1 número
    - Pelo menos 1 caractere especial
    """
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        return False
    return True

# 📝 Mostra os critérios para criar a chave segura
def show_password_criteria():
    print("\n🔐 A senha deve conter:")
    print(" - Pelo menos 8 caracteres")
    print(" - Pelo menos 1 letra maiúscula (A-Z)")
    print(" - Pelo menos 1 letra minúscula (a-z)")
    print(" - Pelo menos 1 número (0-9)")
    print(" - Pelo menos 1 caractere especial (ex: !@#$%^&*)\n")



BASE = "http://127.0.0.1:5000"

print("1 - Registar com ZKP")
print("2 - Login com ZKP")
op = input("Escolha uma opção: ")

username = input("Nome de utilizador: ")

if op == "1":
    show_password_criteria()
segredo = input("🧠 Introduz o teu segredo: ")

# Verifica se o segredo cumpre os critérios
if not is_secure_password(segredo):
    print("❌ A senha não cumpre os critérios de segurança. Tenta novamente.")
    exit()

# ---------------------- REGISTO POR ZKP --------------------------
if op == "1":
    y = generate_keys(segredo)
    r = requests.post(f"{BASE}/zk_register", json={"username": username, "y": str(y)})
    print("🔐 Registo ZKP:", r.json())
    exit()

# ---------------------- LOGIN POR ZKP ----------------------------
if op == "2":
    v, r_val = generate_proof(segredo)
    r1 = requests.post(f"{BASE}/zk_start", json={"username": username, "r": str(r_val)})
    if "c" not in r1.json():
        print("❌ Erro na fase 1:", r1.json())
        exit()
    c = int(r1.json()["c"])
    s = compute_response(v, c, segredo)
    r2 = requests.post(f"{BASE}/zk_verify", json={"username": username, "s": str(s)})
    if "token" not in r2.json():
        print("❌ Verificação falhou:", r2.json())
        exit()
    print("✅ Login ZKP com sucesso!")
    token = r2.json()["token"]
else:
    print("❌ Opção inválida.")
    exit()

# ------------------ CONTINUAR APÓS LOGIN ------------------

headers = {"Authorization": token}

rsa_pem = requests.get(f"{BASE}/rsa_pub").text
rsa_key = serialization.load_pem_public_key(rsa_pem.encode())

aes_key = os.urandom(32)
aes_iv = os.urandom(16)

enc_key = rsa_key.encrypt(
    aes_key,
    asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                      algorithm=hashes.SHA256(), label=None)
)
enc_iv = rsa_key.encrypt(
    aes_iv,
    asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                      algorithm=hashes.SHA256(), label=None)
)

r = requests.post(f"{BASE}/aes_key", headers=headers, json={
    "enc_key": base64.b64encode(enc_key).decode(),
    "enc_iv": base64.b64encode(enc_iv).decode()
})
print("🔐 AES enviada:", r.json())

r = requests.get(f"{BASE}/scratch", headers=headers)
data = r.json()

if "raspadinha" in data:
    encrypted = base64.b64decode(data["raspadinha"])
    print("🎉 Resultado da raspadinha:", decrypt_aes(encrypted, aes_key, aes_iv))
else:
    print("⚠️ Erro:", data.get("error"))

r = requests.get(f"{BASE}/stats", headers=headers)
data = r.json()
print(f"📊 Estatísticas: {data['utilizador']} raspou {data['total_raspadinhas']}x e ganhou {data['total_premios']} prémios!")
