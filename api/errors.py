from __future__ import annotations

from typing import Any


class ApiError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


class DataIntegrityError(ApiError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(503, "data_integrity_error", message, details)


def invalid_parameter(message: str, parameter: str | None = None) -> ApiError:
    details = {"parameter": parameter} if parameter else None
    return ApiError(400, "invalid_parameter", message, details)
