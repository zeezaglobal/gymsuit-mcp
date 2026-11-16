"""Thin async client for the GymSuit backend API.

Endpoints used (all already exist on the backend, no GymSuit changes needed):
- POST /api/mobile/auth/send-otp     {email, mode: "login"}
- POST /api/mobile/auth/verify-login {email, otp} -> MobileAuthResponse
- POST /api/mobile/auth/refresh      {refreshToken} -> MobileAuthResponse
- POST /api/mobile/food/sync         {entries: [...]} -> {synced: n}
- GET  /api/mobile/food/score        ?days&calorieTargetKcal
- DELETE /api/mobile/food/{externalId}
"""

from __future__ import annotations

import httpx


class GymSuitError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class GymSuitClient:
    def __init__(self, base_url: str, transport: httpx.BaseTransport | None = None) -> None:
        # trust_env=False: never route GymSuit calls through an ambient
        # HTTP(S)_PROXY from the environment.
        self._client = httpx.AsyncClient(
            base_url=base_url, transport=transport, timeout=30, trust_env=False
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _request(self, method: str, path: str, token: str | None = None, **kwargs) -> dict | None:
        headers = kwargs.pop("headers", {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        response = await self._client.request(method, path, headers=headers, **kwargs)
        if response.status_code == 204:
            return None
        if 200 <= response.status_code < 300:
            return response.json() if response.content else {}
        detail = self._error_detail(response)
        raise GymSuitError(response.status_code, detail)

    @staticmethod
    def _error_detail(response: httpx.Response) -> str:
        try:
            data = response.json()
            if isinstance(data, dict):
                for key in ("message", "error", "detail"):
                    if data.get(key):
                        return str(data[key])
        except Exception:
            pass
        return (response.text or f"HTTP {response.status_code}").strip()[:300]

    async def send_otp(self, email: str) -> None:
        await self._request(
            "POST", "/api/mobile/auth/send-otp", json={"email": email, "mode": "login"}
        )

    async def verify_login(self, email: str, otp: str) -> dict:
        result = await self._request(
            "POST", "/api/mobile/auth/verify-login", json={"email": email, "otp": otp}
        )
        return result or {}

    async def refresh(self, refresh_token: str) -> dict:
        result = await self._request(
            "POST", "/api/mobile/auth/refresh", json={"refreshToken": refresh_token}
        )
        return result or {}

    async def sync_food(self, access_token: str, entries: list[dict]) -> dict:
        result = await self._request(
            "POST", "/api/mobile/food/sync", token=access_token, json={"entries": entries}
        )
        return result or {}

    async def get_score(self, access_token: str, days: int, calorie_target: int) -> dict:
        result = await self._request(
            "GET",
            "/api/mobile/food/score",
            token=access_token,
            params={"days": days, "calorieTargetKcal": calorie_target},
        )
        return result or {}

    async def delete_food(self, access_token: str, external_id: str) -> None:
        await self._request("DELETE", f"/api/mobile/food/{external_id}", token=access_token)
