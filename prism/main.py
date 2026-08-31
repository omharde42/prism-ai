import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse

from prism.config import settings
from prism.database import init_db
from prism.api.routes import router as api_router

init_db()

app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Register API routes
app.include_router(api_router, prefix="/api")

# Serve dashboard HTML
DASHBOARD_DIR = os.path.join(os.path.dirname(__file__), "dashboard")

@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    dashboard_file = os.path.join(DASHBOARD_DIR, "index.html")
    if os.path.exists(dashboard_file):
        with open(dashboard_file, "r") as f:
            return f.read()
    return "<h1>PRISM Intelligence Platform API</h1>"
