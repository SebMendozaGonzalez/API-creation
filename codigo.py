from fastapi import FastAPI

app = FastAPI()

@app.get("/employee")
async def get_employee():
    return {"id": 1, "name": "John Doe"}

# Run using: uvicorn filename:app --reload
