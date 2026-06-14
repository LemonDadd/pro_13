from fastapi import Depends, HTTPException, status, Request

from app.core.config import settings


def get_api_key(request: Request) -> str:
    api_key = request.headers.get(settings.api_key_header)
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API Key",
        )
    if api_key not in settings.api_keys.values():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API Key",
        )
    return api_key


def get_tenant_id(api_key: str = Depends(get_api_key)) -> str:
    for tenant, key in settings.api_keys.items():
        if key == api_key:
            return tenant
    return settings.default_tenant
