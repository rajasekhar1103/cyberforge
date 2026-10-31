from __future__ import annotations

import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from api.config import ApiConfig
from api.errors import ApiError
from api.routes import router
from api.service import AnalyticsService

logger = logging.getLogger("cyberforge.api")


def _error_body(
    code: str,
    message: str,
    request_id: str | None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details,
            "request_id": request_id,
        }
    }


def create_app(config: ApiConfig | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI) -> Any:
        try:
            yield
        finally:
            await asyncio.to_thread(application.state.analytics.close)

    application = FastAPI(
        title="CyberForge Investigation API",
        version="0.1.0",
        lifespan=lifespan,
    )
    application.state.analytics = AnalyticsService(config or ApiConfig.from_env())

    @application.middleware("http")
    async def request_id_middleware(request: Request, call_next: Any) -> Any:
        request.state.request_id = str(uuid.uuid4())
        response = await call_next(request)
        content_type = response.headers.get("content-type", "")
        if response.status_code < 400 and content_type.startswith("application/json"):
            maximum = application.state.analytics.config.max_response_bytes
            declared_length = response.headers.get("content-length")
            oversized = declared_length is not None and int(declared_length) > maximum
            body = bytearray()
            if not oversized:
                async for chunk in response.body_iterator:
                    chunk_bytes = chunk.encode("utf-8") if isinstance(chunk, str) else chunk
                    if len(body) + len(chunk_bytes) > maximum:
                        oversized = True
                        break
                    body.extend(chunk_bytes)
            if oversized:
                close_iterator = getattr(response.body_iterator, "aclose", None)
                if close_iterator is not None:
                    await close_iterator()
                response = JSONResponse(
                    status_code=413,
                    content=_error_body(
                        "response_too_large",
                        "The response exceeds the configured byte limit",
                        request.state.request_id,
                        {"max_response_bytes": maximum},
                    ),
                )
            else:
                headers = {
                    key: value
                    for key, value in response.headers.items()
                    if key.lower() not in {"content-length", "transfer-encoding"}
                }
                response = Response(
                    content=bytes(body),
                    status_code=response.status_code,
                    headers=headers,
                )
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @application.exception_handler(ApiError)
    async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(
                exc.code,
                exc.message,
                getattr(request.state, "request_id", None),
                exc.details,
            ),
        )

    @application.exception_handler(RequestValidationError)
    async def request_validation_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        errors = [
            {
                "location": [str(part) for part in error.get("loc", ())],
                "message": error.get("msg", "Invalid request parameter"),
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=400,
            content=_error_body(
                "invalid_parameter",
                "One or more request parameters are invalid",
                getattr(request.state, "request_id", None),
                {"errors": errors},
            ),
        )

    @application.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 404:
            code, message = "not_found", "The requested resource was not found"
        elif exc.status_code == 400:
            code, message = "invalid_parameter", "The request is invalid"
        elif exc.status_code == 503:
            code, message = "service_unavailable", "The service is temporarily unavailable"
        else:
            code, message = "internal_error", "The request could not be completed"
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(
                code,
                message,
                getattr(request.state, "request_id", None),
            ),
        )

    @application.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled API request failure", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content=_error_body(
                "internal_error",
                "The request could not be completed",
                getattr(request.state, "request_id", None),
            ),
        )

    application.include_router(router)
    return application


app = create_app()
