from fastapi import FastAPI
import uvicorn

from app.settings import settings

from app.auth.api import router as auth_router

app = FastAPI()
app.include_router(auth_router)

if __name__ == "__main__":
    uvicorn.run(
        app="main:app",
        reload=True,
        host=settings.ALLOWED_HOST,
        port=settings.ALLOWED_PORT,
        # log_level=logging.INFO,
        use_colors=True,
    )
