"""
Minimal API key authentication.

A single shared secret, read from the environment, required on every
request via the X-API-Key header. This is intentionally simple (no user
accounts, no JWT) — appropriate for a single-operator SIEM lab, and still
a real, correctly-implemented access control rather than none at all.
"""

import os
import secrets

from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

API_KEY = os.getenv("API_KEY")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(provided_key: str = Security(api_key_header)):
    if not API_KEY:
        # Fail closed: if the operator forgot to set API_KEY, refuse to
        # run open rather than silently allowing all requests through.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfigured: API_KEY is not set",
        )

    if not provided_key or not secrets.compare_digest(provided_key, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )

    return provided_key