import requests

SERVER_URL = "http://127.0.0.1:8000"

def check_server():
    response = requests.get(SERVER_URL)
    print(response.json())

if __name__ == "__main__":
    check_server()
