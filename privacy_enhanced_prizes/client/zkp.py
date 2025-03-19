import requests
from petlib.ec import EcGroup

G = EcGroup()
SERVER_URL = "http://127.0.0.1:8000/auth"

def register(username, password):
    """ Regista um novo utilizador. """
    response = requests.post(f"{SERVER_URL}/register", json={"username": username, "password": password})
    print(response.json())

def login_zkp(username, password):
    """ Inicia o processo de login usando Prova de Conhecimento Zero. """
    
    # Pedir um desafio ao servidor
    challenge_response = requests.get(f"{SERVER_URL}/challenge")
    challenge = int(challenge_response.json()["challenge"])

    # Gerar a prova usando a senha do utilizador
    secret = G.hash_to_point(password.encode())
    proof = secret.pt_mul(challenge)  # Criar a resposta ao desafio

    # Enviar a resposta ao servidor
    login_response = requests.post(f"{SERVER_URL}/login_zkp", json={
        "username": username,
        "proof": str(proof),
        "challenge": str(challenge)
    })

    if login_response.status_code == 200:
        print(f"Token recebido: {login_response.json()['token']}")
    else:
        print("Falha na autenticação")

if __name__ == "__main__":
    register("user1", "password123")
    login_zkp("user1", "password123")
