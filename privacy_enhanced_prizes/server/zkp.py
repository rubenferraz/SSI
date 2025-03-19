import os
from petlib.ec import EcGroup
from passlib.hash import argon2

# Grupo de curvas elípticas
G = EcGroup()

# Base de dados simulada
users_db = {}

def register_user(username, password):
    """ Regista um utilizador gerando uma chave pública a partir da senha. """
    if username in users_db:
        return {"error": "Utilizador já existe"}

    # Hash da senha para armazenar
    hashed_password = argon2.hash(password)
    
    # Gerar chave secreta a partir da senha (mapeada para um elemento do grupo)
    secret = G.hash_to_point(password.encode())
    public_key = secret.pt_mul(G.order())

    users_db[username] = {"hashed_password": hashed_password, "public_key": public_key}
    return {"message": "Utilizador registado com sucesso"}

def generate_challenge():
    """ Gera um desafio aleatório para o protocolo ZKP. """
    return G.order().random()

def verify_zkp(username, proof, challenge):
    """ Verifica se o utilizador provou conhecer a senha sem a revelar. """
    if username not in users_db:
        return False

    user_data = users_db[username]
    public_key = user_data["public_key"]

    # Recalcula a resposta esperada
    expected_response = public_key.pt_mul(challenge)

    return proof == expected_response
