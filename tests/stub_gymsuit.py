"""Test-only stub of the GymSuit backend API.

Implements just enough of /api/mobile/auth/* and /api/mobile/food/* to
exercise the MCP server end to end, with no real user data.
OTP "123456" always verifies. State is visible at GET /__state.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


class StubState:
    def __init__(self) -> None:
        self.entries: list[dict] = []
        self.workouts: list[dict] = []
        self.otp_sent_to: list[str] = []
        self.counter = 0


def _auth_ok(request: Request) -> bool:
    return (request.headers.get("authorization", "") or "").startswith("Bearer gymsuit-access-")


def create_stub_app(state: StubState) -> Starlette:
    async def send_otp(request: Request) -> JSONResponse:
        body = await request.json()
        state.otp_sent_to.append(body.get("email", ""))
        return JSONResponse({"message": "A 6-digit verification code has been sent to your email."})

    async def verify_login(request: Request) -> JSONResponse:
        body = await request.json()
        if body.get("otp") != "123456":
            return JSONResponse({"message": "Invalid OTP"}, status_code=400)
        state.counter += 1
        n = state.counter
        return JSONResponse(
            {
                "token": f"gymsuit-access-{n}",
                "refreshToken": f"gymsuit-refresh-{n}",
                "role": "OWNER",
                "email": body.get("email", ""),
                "firstName": "Test",
                "lastName": "User",
                "memberId": 9,
                "gymId": 1,
                "gymName": "Test Gym",
            }
        )

    async def refresh(request: Request) -> JSONResponse:
        body = await request.json()
        token = body.get("refreshToken", "")
        if not token.startswith("gymsuit-refresh-"):
            return JSONResponse({"message": "Invalid refresh token"}, status_code=400)
        state.counter += 1
        n = state.counter
        return JSONResponse(
            {
                "token": f"gymsuit-access-{n}",
                "refreshToken": f"gymsuit-refresh-{n}",
                "role": "OWNER",
                "email": "athul.6560@gmail.com",
                "firstName": "Test",
                "lastName": "User",
                "memberId": 9,
                "gymId": 1,
                "gymName": "Test Gym",
            }
        )

    async def sync_food(request: Request) -> JSONResponse:
        if not _auth_ok(request):
            return JSONResponse({"message": "Unauthorized"}, status_code=401)
        body = await request.json()
        entries = body.get("entries", [])
        for entry in entries:
            state.entries = [e for e in state.entries if e["externalId"] != entry["externalId"]]
            state.entries.append(entry)
        return JSONResponse({"synced": len(entries)})

    async def score(request: Request) -> JSONResponse:
        if not _auth_ok(request):
            return JSONResponse({"message": "Unauthorized"}, status_code=401)
        return JSONResponse(
            {
                "score": 78,
                "label": "Optimal",
                "days": 7,
                "components": {"protein": 20, "calories": 20, "balance": 18, "pattern": 20},
                "foodQuality": 85,
            }
        )

    async def delete_food(request: Request) -> JSONResponse:
        if not _auth_ok(request):
            return JSONResponse({"message": "Unauthorized"}, status_code=401)
        external_id = request.path_params["external_id"]
        state.entries = [e for e in state.entries if e["externalId"] != external_id]
        return JSONResponse(status_code=204, content=None)

    async def sync_workout(request: Request) -> JSONResponse:
        if not _auth_ok(request):
            return JSONResponse({"message": "Unauthorized"}, status_code=401)
        body = await request.json()
        saved = []
        for entry in body.get("entries", []):
            state.workouts = [w for w in state.workouts if w["externalId"] != entry["externalId"]]
            # Estimate calories when the caller didn't provide them (like the real backend).
            calories = entry.get("caloriesBurned")
            if not calories:
                mins = entry.get("durationMinutes") or 30
                calories = round(5.0 * 70.0 * (mins / 60.0), 1)
            record = {**entry, "caloriesBurned": calories, "sourceDevice": entry.get("sourceDevice", "MCP")}
            state.workouts.append(record)
            saved.append(record)
        return JSONResponse(saved)

    async def list_workouts(request: Request) -> JSONResponse:
        if not _auth_ok(request):
            return JSONResponse({"message": "Unauthorized"}, status_code=401)
        return JSONResponse(state.workouts)

    async def delete_workout(request: Request) -> JSONResponse:
        if not _auth_ok(request):
            return JSONResponse({"message": "Unauthorized"}, status_code=401)
        external_id = request.path_params["external_id"]
        state.workouts = [w for w in state.workouts if w["externalId"] != external_id]
        return JSONResponse(status_code=204, content=None)

    async def get_state(request: Request) -> JSONResponse:
        return JSONResponse(
            {"entries": state.entries, "workouts": state.workouts,
             "otp_sent_to": state.otp_sent_to, "counter": state.counter}
        )

    return Starlette(
        routes=[
            Route("/api/mobile/auth/send-otp", send_otp, methods=["POST"]),
            Route("/api/mobile/auth/verify-login", verify_login, methods=["POST"]),
            Route("/api/mobile/auth/refresh", refresh, methods=["POST"]),
            Route("/api/mobile/food/sync", sync_food, methods=["POST"]),
            Route("/api/mobile/food/score", score, methods=["GET"]),
            Route("/api/mobile/food/{external_id}", delete_food, methods=["DELETE"]),
            Route("/api/mobile/workout/sync", sync_workout, methods=["POST"]),
            Route("/api/mobile/workout", list_workouts, methods=["GET"]),
            Route("/api/mobile/workout/{external_id}", delete_workout, methods=["DELETE"]),
            Route("/__state", get_state, methods=["GET"]),
        ]
    )
