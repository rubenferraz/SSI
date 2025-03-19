from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from passlib.hash import argon2
import jwt
import time

router = APIRouter()

SECRET_KEY = "superseguro"

users_db = {}

# Modelo Pydantic para receber os dados corretamente
class UserData(BaseModel):
    username: str
    password: str

def create_jwt(username: str):
    payload = {
        "sub": username,
        "exp": time.time() + 3600
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

@router.post("/register")
def register(user: UserData):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Utilizador já existe")

    hashed_password = argon2.hash(user.password)
    users_db[user.username] = hashed_password
    return {"message": "Utilizador registado com sucesso"}

@router.post("/login")
def login(user: UserData):
    if user.username not in users_db or not argon2.verify(user.password, users_db[user.username]):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    token = create_jwt(user.username)
    return {"token": token}
