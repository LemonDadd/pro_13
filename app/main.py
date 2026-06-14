from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import init_db
from app.api.detect import router as detect_router
from app.api.mask import router as mask_router
from app.api.batch import router as batch_router
from app.api.stats import router as stats_router
from app.rules.engine import get_rule_engine
from app.workers.batch_worker import get_batch_worker


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        init_db()
    except Exception as e:
        print(f"Warning: Database initialization failed: {e}")

    get_rule_engine()

    worker = get_batch_worker()
    worker.start()

    yield

    worker.stop()


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="敏感数据检测与脱敏 API",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(detect_router, prefix="/v1")
    app.include_router(mask_router, prefix="/v1")
    app.include_router(batch_router, prefix="/v1")
    app.include_router(stats_router, prefix="/v1")

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": settings.app_version}

    return app


app = create_app()
