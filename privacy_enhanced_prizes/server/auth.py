from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import jwt
import time
from server.zkp import register_user, generate_challenge, verify_zkp

router = APIRouter()
SECRET_KEY = "superseguro"

# Estruturas de dados para requests
class RegisterData(BaseModel):
    username: str
    password: str

class LoginZKPData(BaseModel):
    username: str
    proof: str
    challenge: str

def create_jwt(username: str):
    payload = {
        "sub": username,
        "exp": time.time() + 3600
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

@router.post("/register")
def register(data: RegisterData):
    return register_user(data.username, data.password)

@router.get("/challenge")
def get_challenge():
    """ Envia um desafio ao cliente para iniciar o ZKP. """
    challenge = generate_challenge()
    return {"challenge": str(challenge)}

@router.post("/login_zkp")
def login(data: LoginZKPData):
    """ Verifica se a prova de conhecimento é válida. """
    if verify_zkp(data.username, int(data.proof), int(data.challenge)):
        token = create_jwt(data.username)
        return {"token": token}
    
    raise HTTPException(status_code=401, detail="Prova inválida")
