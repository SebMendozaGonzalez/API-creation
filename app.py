from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return("Hello World")

@app.get("/employee")
async def get_employee():
    return {"id": 1, "name": "John Doe"}

@app.get(api:="/api")
def hit_api():
    return {"Arrived at:": api}
