"""Standardized Application Exceptions and Global Exception Handlers.

Module: backend.app.core.exceptions
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-005 Section 7: Shared API Conventions & Standard Error Envelope
- Master Prompt Section 9.5: Error Handling & Fail-Closed Posture
"""

import logging
import uuid
from typing import Any, Dict, List, Optional, Union
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("amsc.exceptions")


# --- Base & Concrete Application Exceptions ---

class AMSCException(Exception):
    """Base exception for all domain and platform errors in AMSC."""

    def __init__(
        self,
        message: str = "An application error occurred.",
        code: str = "AMSC_APPLICATION_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Union[Dict[str, Any], List[Any], str]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details


class NotFoundError(AMSCException):
    """Raised when a requested resource is not found in the tenant scope."""

    def __init__(
        self,
        message: str = "The requested resource was not found.",
        details: Optional[Union[Dict[str, Any], List[Any], str]] = None,
    ):
        super().__init__(
            message=message,
            code="RESOURCE_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
            details=details,
        )


class ValidationError(AMSCException):
    """Raised when input parameters fail business validation rules."""

    def __init__(
        self,
        message: str = "Invalid request parameters.",
        details: Optional[Union[Dict[str, Any], List[Any], str]] = None,
    ):
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            status_code=status.HTTP_400_BAD_REQUEST,
            details=details,
        )


class AuthenticationError(AMSCException):
    """Raised when authentication credentials are missing, invalid, or expired."""

    def __init__(
        self,
        message: str = "Authentication credentials are invalid or missing.",
        details: Optional[Union[Dict[str, Any], List[Any], str]] = None,
    ):
        super().__init__(
            message=message,
            code="AUTHENTICATION_FAILED",
            status_code=status.HTTP_401_UNAUTHORIZED,
            details=details,
        )


class ForbiddenError(AMSCException):
    """Raised when an authenticated caller lacks permissions for an operation."""

    def __init__(
        self,
        message: str = "You do not have permission to perform this action.",
        details: Optional[Union[Dict[str, Any], List[Any], str]] = None,
    ):
        super().__init__(
            message=message,
            code="FORBIDDEN_ACTION",
            status_code=status.HTTP_403_FORBIDDEN,
            details=details,
        )


class TenantAccessForbiddenError(AMSCException):
    """Raised when cross-tenant boundary access is detected or rejected."""

    def __init__(
        self,
        message: str = "Access to the requested tenant workspace is forbidden.",
        details: Optional[Union[Dict[str, Any], List[Any], str]] = None,
    ):
        super().__init__(
            message=message,
            code="TENANT_ACCESS_FORBIDDEN",
            status_code=status.HTTP_403_FORBIDDEN,
            details=details,
        )


class PolicyDeniedError(AMSCException):
    """Raised when the security policy engine blocks a proposed agent tool action."""

    def __init__(
        self,
        message: str = "The proposed action was blocked by security policy.",
        reasons: Optional[List[str]] = None,
    ):
        details = {"reasons": reasons or []} if reasons else None
        super().__init__(
            message=message,
            code="POLICY_EVALUATION_DENIED",
            status_code=status.HTTP_403_FORBIDDEN,
            details=details,
        )


class SecurityDependencyError(AMSCException):
    """Raised when a security engine dependency is offline, triggering fail-closed."""

    def __init__(
        self,
        message: str = "Required security verification service is currently unavailable.",
        details: Optional[Union[Dict[str, Any], List[Any], str]] = None,
    ):
        super().__init__(
            message=message,
            code="SECURITY_DEPENDENCY_UNAVAILABLE",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            details=details,
        )


# --- Helper: Build Canonical Error Envelope & Headers ---

def build_error_envelope(
    code: str,
    message: str,
    request_id: Optional[str] = None,
    details: Optional[Union[Dict[str, Any], List[Any], str]] = None,
) -> Dict[str, Any]:
    """Format canonical error JSON matching AMSC-DOC-005 Section 7.

    Structure:
    {
      "error": {
        "code": "...",
        "message": "...",
        "request_id": "...",
        "details": ...
      }
    }
    """
    return {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id or f"req-{uuid.uuid4().hex[:8]}",
            "details": details,
        }
    }


def get_trace_context(request: Request) -> tuple[str, Optional[str]]:
    """Extract request_id and optional trace_id from request state or sanitized headers."""
    req_id = getattr(request.state, "request_id", None)
    if not req_id:
        raw_req = (
            request.headers.get("x-request-id")
            or request.headers.get("x-trace-id")
            or request.headers.get("x-correlation-id")
        )
        if raw_req:
            import re
            if re.match(r"^[a-zA-Z0-9_\-\.]{1,128}$", str(raw_req).strip()):
                req_id = str(raw_req).strip()
        if not req_id:
            req_id = f"req-{uuid.uuid4().hex[:8]}"

    trace_id = getattr(request.state, "trace_id", None)
    if not trace_id:
        raw_trace = request.headers.get("x-trace-id") or request.headers.get("x-correlation-id")
        if raw_trace:
            import re
            if re.match(r"^[a-zA-Z0-9_\-\.]{1,128}$", str(raw_trace).strip()):
                trace_id = str(raw_trace).strip()

    return str(req_id), str(trace_id) if trace_id else None


def get_request_id(request: Request) -> str:
    """Retrieve primary request ID from request state or headers."""
    req_id, _ = get_trace_context(request)
    return req_id


def build_response_headers(request: Request, req_id: str) -> Dict[str, str]:
    """Construct response headers guaranteeing X-Request-ID and trace context propagation."""
    headers = {"X-Request-ID": req_id}
    _, trace_id = get_trace_context(request)
    if trace_id:
        headers["X-Trace-ID"] = trace_id
    return headers


# --- Global Exception Handlers ---

async def amsc_exception_handler(request: Request, exc: AMSCException) -> JSONResponse:
    """Handler for domain-specific AMSCException instances."""
    req_id, _ = get_trace_context(request)
    headers = build_response_headers(request, req_id)
    logger.warning(
        f"Domain exception [{exc.code}] HTTP {exc.status_code} for {request.method} {request.url.path} (request_id={req_id}): {exc.message}"
    )
    envelope = build_error_envelope(
        code=exc.code,
        message=exc.message,
        request_id=req_id,
        details=exc.details,
    )
    return JSONResponse(status_code=exc.status_code, content=envelope, headers=headers)


async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Handler for Starlette/FastAPI HTTPException instances."""
    req_id, _ = get_trace_context(request)
    headers = build_response_headers(request, req_id)

    # Map common status codes to standardized codes
    code_map = {
        status.HTTP_400_BAD_REQUEST: "BAD_REQUEST",
        status.HTTP_401_UNAUTHORIZED: "AUTHENTICATION_REQUIRED",
        status.HTTP_403_FORBIDDEN: "FORBIDDEN",
        status.HTTP_404_NOT_FOUND: "RESOURCE_NOT_FOUND",
        status.HTTP_405_METHOD_NOT_ALLOWED: "METHOD_NOT_ALLOWED",
        status.HTTP_429_TOO_MANY_REQUESTS: "RATE_LIMIT_EXCEEDED",
        status.HTTP_500_INTERNAL_SERVER_ERROR: "INTERNAL_SERVER_ERROR",
        status.HTTP_503_SERVICE_UNAVAILABLE: "SERVICE_UNAVAILABLE",
    }
    error_code = code_map.get(exc.status_code, f"HTTP_{exc.status_code}")

    logger.warning(
        f"HTTP error [{error_code}] status {exc.status_code} for {request.method} {request.url.path} (request_id={req_id}): {exc.detail}"
    )

    envelope = build_error_envelope(
        code=error_code,
        message=str(exc.detail),
        request_id=req_id,
        details=None,
    )
    return JSONResponse(status_code=exc.status_code, content=envelope, headers=headers)


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handler for Pydantic schema validation failures.

    Returns HTTP 400 Bad Request matching AMSC-DOC-005 Section 7.
    """
    req_id, _ = get_trace_context(request)
    headers = build_response_headers(request, req_id)

    # Sanitize and simplify error entries to avoid exposing sensitive internal details
    sanitized_errors = []
    for err in exc.errors():
        sanitized_errors.append({
            "loc": [str(loc) for loc in err.get("loc", [])],
            "msg": err.get("msg", "Invalid value"),
            "type": err.get("type", "value_error"),
        })

    logger.info(
        f"Validation error for {request.method} {request.url.path} (request_id={req_id}): {sanitized_errors}"
    )

    envelope = build_error_envelope(
        code="VALIDATION_ERROR",
        message="Request validation failed. Please check your parameters.",
        request_id=req_id,
        details={"validation_errors": sanitized_errors},
    )
    return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=envelope, headers=headers)


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler for unhandled exceptions.

    CRITICAL SECURITY INVARIANT:
    Never expose Python tracebacks, internal file system paths, or infrastructure
    credentials to API clients. Always log full error server-side and return safe generic message.
    """
    req_id, _ = get_trace_context(request)
    headers = build_response_headers(request, req_id)

    logger.exception(
        f"Unhandled server error on {request.method} {request.url.path} (request_id={req_id}): {exc}"
    )

    envelope = build_error_envelope(
        code="INTERNAL_SERVER_ERROR",
        message="An unexpected server error occurred. The incident has been recorded.",
        request_id=req_id,
        details=None,
    )
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=envelope, headers=headers)


def register_exception_handlers(app: FastAPI) -> None:
    """Register all standard exception handlers on the FastAPI application."""
    app.add_exception_handler(AMSCException, amsc_exception_handler)
    app.add_exception_handler(StarletteHTTPException, starlette_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
