"""Standardized Application Exceptions and Global Exception Handlers.

Module: backend.app.core.exceptions
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-005 Section 7: Shared API Conventions & Standard Error Envelope
- Master Prompt Section 9.5: Error Handling & Fail-Closed Posture
"""

import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Union
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
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


class RateLimitExceededError(AMSCException):
    """Raised when an operation exceeds rate-limiting thresholds."""

    def __init__(
        self,
        message: str = "Request rate limit exceeded. Please try again later.",
        retry_after: Optional[int] = None,
        details: Optional[Union[Dict[str, Any], List[Any], str]] = None,
    ):
        self.retry_after = retry_after
        super().__init__(
            message=message,
            code="RATE_LIMIT_EXCEEDED",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            details=details,
        )


# --- Allowlisted Safe Public Error Messages ---

SAFE_PUBLIC_MESSAGES: Dict[str, str] = {
    "AUTHENTICATION_FAILED": "Invalid email, password, or tenant access.",
    "AUTHENTICATION_REQUIRED": "Authentication required. Please provide a valid Bearer token.",
    "INVALID_TOKEN": "Invalid or expired authentication token.",
    "FORBIDDEN_ACTION": "You do not have permission to perform this action.",
    "FORBIDDEN": "Access denied. Insufficient permissions for this action.",
    "TENANT_ACCESS_FORBIDDEN": "Access to the requested tenant workspace is forbidden.",
    "TENANT_ACCESS_DENIED": "Access to the requested tenant workspace is forbidden.",
    "RESOURCE_NOT_FOUND": "Not Found: The requested resource was not found.",
    "VALIDATION_ERROR": "Request validation failed. Please check your parameters.",
    "POLICY_EVALUATION_DENIED": "The proposed action was blocked by security policy.",
    "SECURITY_DEPENDENCY_UNAVAILABLE": "Required security verification service is currently unavailable.",
    "RATE_LIMIT_EXCEEDED": "Request rate limit exceeded. Please try again later.",
    "INTERNAL_SERVER_ERROR": "An unexpected server error occurred. The incident has been recorded.",
    "SERVICE_UNAVAILABLE": "Service temporarily unavailable.",
    "BAD_REQUEST": "Invalid request parameters.",
    "METHOD_NOT_ALLOWED": "Method not allowed for this resource.",
    "CONFLICT": "The requested operation conflicts with existing resource state.",
    "MEMORY_INTEGRITY_VIOLATION": "Cryptographic integrity verification failed for the requested memory record.",
    "INVALID_PROVENANCE": "Invalid provenance relationship specified.",
}

DEFAULT_SAFE_PUBLIC_MESSAGE = "An application error occurred. The incident has been recorded."

# Explicit allowlist for HTTP protocol response headers
SAFE_PROTOCOL_HEADERS = {"www-authenticate", "allow", "retry-after"}


def sanitize_details(details: Any) -> Any:
    """Recursively scrub sensitive keys and credential patterns from error details."""
    if details is None:
        return None
    sensitive_markers = ("password", "token", "secret", "api_key", "api-key", "authorization", "bearer", "credential", "priv_key")
    if isinstance(details, dict):
        sanitized = {}
        for k, v in details.items():
            k_lower = str(k).lower()
            if any(marker in k_lower for marker in sensitive_markers):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_details(v)
        return sanitized
    elif isinstance(details, (list, tuple)):
        return [sanitize_details(item) for item in details]
    elif isinstance(details, str):
        lower = details.lower()
        if any(marker in lower for marker in sensitive_markers):
            return "[REDACTED]"
        return details
    return details


# --- OpenAPI Reusable Error Response Schemas ---

class ErrorDetail(BaseModel):
    """Canonical error payload matching AMSC-DOC-005 Section 7."""

    code: str = Field(
        description="Stable machine-readable error code",
        examples=["POLICY_EVALUATION_DENIED"],
    )
    message: str = Field(
        description="Sanitized human-readable error description",
        examples=["The proposed action was blocked by security policy."],
    )
    request_id: str = Field(
        description="Correlation identifier for request tracing",
        examples=["req-991204"],
    )
    details: Optional[Union[Dict[str, Any], List[Any], str]] = Field(
        default=None,
        description="Optional sanitized error details (e.g. validation error list)",
    )


class ErrorResponse(BaseModel):
    """Canonical error response envelope matching AMSC-DOC-005 Section 7."""

    error: ErrorDetail = Field(description="Standardized error body")


API_ERROR_RESPONSES: Dict[int | str, Dict[str, Any]] = {
    400: {"model": ErrorResponse, "description": "Bad Request: Schema validation failed or malformed parameters."},
    401: {"model": ErrorResponse, "description": "Unauthorized: Missing, invalid, or expired Bearer authentication token."},
    403: {"model": ErrorResponse, "description": "Forbidden: Tenant boundary violation, insufficient role, or blocked by security policy."},
    404: {"model": ErrorResponse, "description": "Not Found: The requested resource does not exist within the tenant scope."},
    405: {"model": ErrorResponse, "description": "Method Not Allowed: The HTTP method is not supported for this endpoint."},
    409: {"model": ErrorResponse, "description": "Conflict: Resource conflict, duplicate proposal, or idempotency fingerprint mismatch."},
    422: {"model": ErrorResponse, "description": "Unprocessable Content: Semantic validation or parameter constraint violation."},
    429: {"model": ErrorResponse, "description": "Too Many Requests: Rate limit exceeded for IP, account, or tenant."},
    500: {"model": ErrorResponse, "description": "Internal Server Error: Unexpected internal server failure (generic sanitized response)."},
    503: {"model": ErrorResponse, "description": "Service Unavailable: Mandatory security verification or database service offline."},
}


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
            if re.match(r"^[a-zA-Z0-9_\-\.]{1,128}$", str(raw_req).strip()):
                req_id = str(raw_req).strip()
        if not req_id:
            req_id = f"req-{uuid.uuid4().hex[:8]}"

    trace_id = getattr(request.state, "trace_id", None)
    if not trace_id:
        raw_trace = request.headers.get("x-trace-id") or request.headers.get("x-correlation-id")
        if raw_trace:
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
    """Handler for domain-specific AMSCException instances.

    Strictly returns allowlisted public error messages. Never exposes arbitrary exc.message or exc.details to clients.
    Logs safe event code, HTTP status, and correlation metadata without appending raw exception message text.
    """
    req_id, _ = get_trace_context(request)
    headers = build_response_headers(request, req_id)

    # Attach validated Retry-After header if present on the exception (e.g. for rate limiting)
    retry_after = getattr(exc, "retry_after", None)
    if retry_after is not None:
        val_str = str(retry_after).strip()
        if re.match(r"^\d{1,6}$", val_str):
            headers["Retry-After"] = val_str

    # Production-safe logging: log safe event code and correlation ID without echoing raw exception message text
    logger.warning(
        f"Domain exception [{exc.code}] HTTP {exc.status_code} for {request.method} {request.url.path} (request_id={req_id})"
    )

    # Strict allowlist mapping
    safe_message = SAFE_PUBLIC_MESSAGES.get(exc.code, DEFAULT_SAFE_PUBLIC_MESSAGE)

    # Strictly disallow arbitrary or unredacted details to leak
    safe_details = None
    if exc.code == "VALIDATION_ERROR" and isinstance(exc.details, dict):
        safe_details = sanitize_details(exc.details)

    envelope = build_error_envelope(
        code=exc.code,
        message=safe_message,
        request_id=req_id,
        details=safe_details,
    )
    return JSONResponse(status_code=exc.status_code, content=envelope, headers=headers)


def sanitize_validation_message(msg: str, input_val: Any = None) -> str:
    """Ensure validation error message does not reflect raw sensitive inputs or credentials."""
    sanitized = msg
    if input_val is not None:
        if isinstance(input_val, (str, int, float)):
            s_input = str(input_val)
            if s_input and len(s_input) >= 3 and s_input in sanitized:
                sanitized = sanitized.replace(s_input, "[REDACTED]")
        elif isinstance(input_val, (dict, list)):
            s_input = str(input_val)
            if s_input in sanitized:
                sanitized = sanitized.replace(s_input, "[REDACTED]")

    lower = sanitized.lower()
    sensitive_markers = ["password", "token", "secret", "api_key", "bearer", "authorization"]
    if any(marker in lower for marker in sensitive_markers):
        if "'" in sanitized or '"' in sanitized:
            sanitized = re.sub(r"['\"][^'\"]*['\"]", "'[REDACTED]'", sanitized)
        # Redact unquoted credentials following key: value patterns
        sanitized = re.sub(r"(?i)\b(password|token|secret|api[_-]?key|bearer|authorization)\s*[:=]\s*\S+", r"\1: [REDACTED]", sanitized)
    return sanitized


async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Handler for Starlette/FastAPI HTTPException instances.

    Strictly maps HTTP status codes to allowlisted error codes and safe messages. Never exposes arbitrary exc.detail.
    Preserves allowlisted protocol headers (WWW-Authenticate, Allow, Retry-After).
    """
    req_id, _ = get_trace_context(request)
    headers = build_response_headers(request, req_id)

    # Safely copy explicitly allowlisted protocol headers only
    if getattr(exc, "headers", None):
        for k, v in exc.headers.items():
            k_lower = k.lower()
            if k_lower in SAFE_PROTOCOL_HEADERS:
                val = str(v).strip()
                if k_lower == "retry-after":
                    if re.match(r"^\d{1,6}$", val):
                        headers[k] = val
                else:
                    # Scrub CR/LF from any header values to prevent header injection
                    headers[k] = val.replace("\r", "").replace("\n", "")

    # Map common status codes to standardized codes
    code_map = {
        status.HTTP_400_BAD_REQUEST: "BAD_REQUEST",
        status.HTTP_401_UNAUTHORIZED: "AUTHENTICATION_REQUIRED",
        status.HTTP_403_FORBIDDEN: "FORBIDDEN",
        status.HTTP_404_NOT_FOUND: "RESOURCE_NOT_FOUND",
        status.HTTP_405_METHOD_NOT_ALLOWED: "METHOD_NOT_ALLOWED",
        status.HTTP_409_CONFLICT: "CONFLICT",
        status.HTTP_422_UNPROCESSABLE_ENTITY: "VALIDATION_ERROR",
        status.HTTP_429_TOO_MANY_REQUESTS: "RATE_LIMIT_EXCEEDED",
        status.HTTP_500_INTERNAL_SERVER_ERROR: "INTERNAL_SERVER_ERROR",
        status.HTTP_503_SERVICE_UNAVAILABLE: "SERVICE_UNAVAILABLE",
    }
    error_code = code_map.get(exc.status_code, f"HTTP_{exc.status_code}")

    logger.warning(
        f"HTTP error [{error_code}] status {exc.status_code} for {request.method} {request.url.path} (request_id={req_id})"
    )

    safe_msg = SAFE_PUBLIC_MESSAGES.get(error_code, DEFAULT_SAFE_PUBLIC_MESSAGE)

    envelope = build_error_envelope(
        code=error_code,
        message=safe_msg,
        request_id=req_id,
        details=None,
    )
    return JSONResponse(status_code=exc.status_code, content=envelope, headers=headers)


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handler for Pydantic schema validation failures.

    Returns HTTP 400 Bad Request matching AMSC-DOC-005 Section 7.
    Sanitizes field locations, stable error codes, and messages; strictly prevents raw input reflection.
    """
    req_id, _ = get_trace_context(request)
    headers = build_response_headers(request, req_id)

    # Sanitize and simplify error entries to avoid exposing sensitive internal details or reflected credentials
    sanitized_errors = []
    for err in exc.errors():
        sanitized_errors.append({
            "loc": [str(loc) for loc in err.get("loc", [])],
            "msg": sanitize_validation_message(err.get("msg", "Invalid value"), err.get("input")),
            "type": str(err.get("type", "value_error")),
        })

    logger.info(
        f"Validation error for {request.method} {request.url.path} (request_id={req_id}): {len(sanitized_errors)} field error(s)"
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
    credentials to API clients. Always log safe structured error server-side and return safe generic message.
    The exception handler itself must never fail.
    """
    try:
        req_id, _ = get_trace_context(request)
        headers = build_response_headers(request, req_id)
        exc_class = exc.__class__.__name__

        # Production-safe logging: log structured error without raw traceback or raw exception text
        logger.error(
            f"Unhandled server error [{exc_class}] on {request.method} {request.url.path} (request_id={req_id})",
            exc_info=False,
        )

        envelope = build_error_envelope(
            code="INTERNAL_SERVER_ERROR",
            message="An unexpected server error occurred. The incident has been recorded.",
            request_id=req_id,
            details=None,
        )
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=envelope, headers=headers)
    except Exception:
        # Emergency fail-closed static response to guarantee the handler itself never crashes ASGI
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected server error occurred. The incident has been recorded.",
                    "request_id": f"req-{uuid.uuid4().hex[:8]}",
                    "details": None,
                }
            },
        )


def register_exception_handlers(app: FastAPI) -> None:
    """Register all standard exception handlers on the FastAPI application."""
    app.add_exception_handler(AMSCException, amsc_exception_handler)
    app.add_exception_handler(StarletteHTTPException, starlette_http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
