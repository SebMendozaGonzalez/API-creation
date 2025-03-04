from fastapi import FastAPI

app = FastAPI()

@app.get("/")
async def public_route():
    return {"message": "Public API is accessible without authentication"}

@app.get("/protected")
async def protected_route():
    return {"message": "This should require authentication, but we removed it for testing."}
