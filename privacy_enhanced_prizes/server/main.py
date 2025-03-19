from fastapi import FastAPI
from server.auth import router as auth_router

app = FastAPI()

app.include_router(auth_router, prefix="/auth")

@app.get("/")
def read_root():
    return {"message": "Servidor PrivacyEnhancedPrizes ativo!"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
