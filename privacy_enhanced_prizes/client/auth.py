import requests

SERVER_URL = "http://127.0.0.1:8000/auth"

def register(username, password):
    response = requests.post(f"{SERVER_URL}/register", json={"username": username, "password": password})
    print(response.json())

def login(username, password):
    response = requests.post(f"{SERVER_URL}/login", json={"username": username, "password": password})
    if response.status_code == 200:
        print(f"Token recebido: {response.json()['token']}")
    else:
        print("Falha na autenticação")

if __name__ == "__main__":
    register("user1", "password123")
    login("user1", "password123")
