from fastapi import FastAPI
import uvicorn

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}


if __name__ == "__main__":
    uvicorn.run(
        app="main:app",
        reload=True,
        # host=settings.ALLOWED_HOST,
        host="0.0.0.0",
        # debug=settings.DEBUG,
        # port=settings.ALLOWED_PORT,
        port=8000,
        # log_level=logging.INFO,
        use_colors=True,
    )
