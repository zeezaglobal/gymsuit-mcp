"""GymSuit MCP tools.

Every tool runs as the user authenticated on the /mcp endpoint: the user
identity comes from the validated MCP access token (set on a ContextVar by
the auth middleware), never from a tool argument. GymSuit access tokens
are refreshed automatically when the backend answers 401.
"""

from __future__ import annotations

import contextvars
import datetime
import re
import uuid
from typing import Literal

from fastmcp import FastMCP

from .config import Settings
from .crypto import decrypt, encrypt
from .gymsuit import GymSuitClient, GymSuitError
from .store import Store

current_gymsuit_email: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "gymsuit_email", default=None
)

MEALS = ("BREAKFAST", "LUNCH", "DINNER", "SNACK")


def _require_email() -> str:
    email = current_gymsuit_email.get()
    if not email:
        raise ValueError("Not authenticated: this tool needs a signed-in GymSuit user.")
    return email


async def _with_gymsuit(
    settings: Settings, store: Store, gymsuit: GymSuitClient, email: str, fn
):
    """Run fn(access_token), refreshing the GymSuit token once on a 401."""
    user = await store.get_gymsuit_user(email)
    if user is None:
        raise ValueError(f"No linked GymSuit account for {email}. Sign in again.")
    secret = settings.secret_key
    try:
        return await fn(decrypt(secret, user["access_token_enc"]))
    except GymSuitError as exc:
        if exc.status != 401:
            raise
        refreshed = await gymsuit.refresh(decrypt(secret, user["refresh_token_enc"]))
        await store.update_gymsuit_tokens(
            email,
            encrypt(secret, refreshed["token"]),
            encrypt(secret, refreshed["refreshToken"]),
        )
        return await fn(refreshed["token"])


def create_mcp_server(settings: Settings, store: Store, gymsuit: GymSuitClient) -> FastMCP:
    mcp = FastMCP("GymSuit")

    @mcp.tool(
        description=(
            "Log one meal into the signed-in user's GymSuit food log, with full "
            "nutrition values. The entry appears in the GymSuit app's food log, "
            "the eating-habit score, and the trainer progress page. "
            "record_date is YYYY-MM-DD and defaults to today (server date); "
            "pass the user's local date when it matters."
        )
    )
    async def log_food(
        meal: Literal["BREAKFAST", "LUNCH", "DINNER", "SNACK"],
        dish_name: str,
        calories: int,
        protein_g: float,
        carbs_g: float,
        fat_g: float,
        record_date: str | None = None,
        photo_base64: str | None = None,
    ) -> dict:
        email = _require_email()
        if meal not in MEALS:
            raise ValueError(f"meal must be one of {', '.join(MEALS)}")
        if calories <= 0:
            raise ValueError("calories must be greater than 0")
        if min(protein_g, carbs_g, fat_g) < 0:
            raise ValueError("protein, carbs and fat must be 0 or more")
        if record_date is None:
            record_date = datetime.date.today().isoformat()
        elif not re.fullmatch(r"\d{4}-\d{2}-\d{2}", record_date):
            raise ValueError("record_date must be YYYY-MM-DD")
        external_id = f"mcp-{uuid.uuid4().hex[:20]}"
        entry = {
            "externalId": external_id,
            "recordDate": record_date,
            "meal": meal,
            "dishName": dish_name,
            "calories": calories,
            "proteinG": protein_g,
            "carbsG": carbs_g,
            "fatG": fat_g,
        }
        if photo_base64:
            entry["photoBase64"] = photo_base64

        async def _sync(access_token: str) -> dict:
            return await gymsuit.sync_food(access_token, [entry])

        result = await _with_gymsuit(settings, store, gymsuit, email, _sync)
        return {
            "synced": result.get("synced", 0),
            "external_id": external_id,
            "record_date": record_date,
            "meal": meal,
            "dish_name": dish_name,
            "calories": calories,
            "protein_g": protein_g,
            "carbs_g": carbs_g,
            "fat_g": fat_g,
        }

    @mcp.tool(
        description=(
            "Read the signed-in user's eating-habit score (0-100) from food "
            "logged over the trailing days (default 7, max 30). Scores protein, "
            "calories vs the target, macro balance and meal pattern. Returns null "
            "score with label 'No data yet' when nothing was logged."
        )
    )
    async def get_eating_score(days: int = 7, calorie_target_kcal: int = 2000) -> dict:
        email = _require_email()
        if not 1 <= days <= 30:
            raise ValueError("days must be between 1 and 30")
        if calorie_target_kcal <= 0:
            raise ValueError("calorie_target_kcal must be greater than 0")

        async def _score(access_token: str) -> dict:
            return await gymsuit.get_score(access_token, days, calorie_target_kcal)

        return await _with_gymsuit(settings, store, gymsuit, email, _score)

    @mcp.tool(
        description=(
            "Delete one food entry the caller logged through this server, by the "
            "external_id returned from log_food. Use it to correct a wrong entry, "
            "then log the corrected one."
        )
    )
    async def delete_food_entry(external_id: str) -> dict:
        email = _require_email()
        if not external_id:
            raise ValueError("external_id is required")

        async def _delete(access_token: str) -> None:
            await gymsuit.delete_food(access_token, external_id)

        await _with_gymsuit(settings, store, gymsuit, email, _delete)
        return {"deleted": external_id}

    @mcp.tool(
        description=(
            "Log one workout into the signed-in user's GymSuit workout log. "
            "Two kinds: STRENGTH (an exercise with sets) needs title (e.g. "
            "'Bench Press'), sets, and reps (reps per set); pass weight_kg to "
            "record the load. CARDIO (running, cycling, swimming, walking, "
            "rowing, ...) needs title (the activity) and duration_minutes; pass "
            "distance_km if known. Calorie burn is estimated automatically from "
            "the activity and the user's body weight unless you pass "
            "calories_burned. record_date is YYYY-MM-DD (default today). The "
            "workout appears in the GymSuit app's workout log and trainer "
            "progress page. Returns the external_id (for delete_workout_entry) "
            "and the calories burned."
        )
    )
    async def log_workout(
        title: str,
        type: Literal["STRENGTH", "CARDIO"] = "STRENGTH",
        sets: int | None = None,
        reps: int | None = None,
        weight_kg: float | None = None,
        duration_minutes: int | None = None,
        distance_km: float | None = None,
        record_date: str | None = None,
        calories_burned: float | None = None,
    ) -> dict:
        email = _require_email()
        title = (title or "").strip()
        if not title:
            raise ValueError("title is required (e.g. 'Bench Press', 'Running')")
        if record_date is None:
            record_date = datetime.date.today().isoformat()
        elif not re.fullmatch(r"\d{4}-\d{2}-\d{2}", record_date):
            raise ValueError("record_date must be YYYY-MM-DD")

        set_count = total_reps = total_volume = None
        display_title = title
        if type == "STRENGTH":
            if sets is None or sets <= 0:
                raise ValueError("strength workouts need sets >= 1")
            if reps is None or reps <= 0:
                raise ValueError("strength workouts need reps >= 1 (reps per set)")
            set_count = sets
            total_reps = sets * reps
            if weight_kg is not None and weight_kg > 0:
                total_volume = sets * reps * weight_kg
            if duration_minutes is None:
                duration_minutes = max(sets * 3, 1)  # ~3 min per set incl. rest
        else:  # CARDIO
            if duration_minutes is None or duration_minutes <= 0:
                raise ValueError("cardio workouts need duration_minutes >= 1")
            if distance_km is not None and distance_km > 0:
                display_title = f"{title} · {distance_km:g} km"

        entry: dict = {
            "externalId": f"mcp-{uuid.uuid4().hex[:20]}",
            "title": display_title,
            "startTime": f"{record_date}T12:00:00",
            "durationMinutes": duration_minutes,
            "setCount": set_count,
            "totalReps": total_reps,
            "totalVolumeKg": total_volume,
            "sourceDevice": "MCP",
        }
        if calories_burned is not None and calories_burned > 0:
            entry["caloriesBurned"] = calories_burned

        async def _sync(access_token: str) -> list:
            return await gymsuit.sync_workout(access_token, [entry])

        saved = await _with_gymsuit(settings, store, gymsuit, email, _sync)
        record = saved[0] if saved else {}
        return {
            "external_id": entry["externalId"],
            "title": display_title,
            "type": type,
            "record_date": record_date,
            "sets": set_count,
            "reps_per_set": reps if type == "STRENGTH" else None,
            "total_reps": total_reps,
            "total_volume_kg": total_volume,
            "duration_minutes": duration_minutes,
            "calories_burned": record.get("caloriesBurned"),
        }

    @mcp.tool(
        description=(
            "List the signed-in user's workouts logged over the trailing days "
            "(default 30, max 90), newest first, with calories, sets/reps and "
            "duration."
        )
    )
    async def get_workouts(days: int = 30) -> list:
        email = _require_email()
        if not 1 <= days <= 90:
            raise ValueError("days must be between 1 and 90")
        from_date = (datetime.date.today() - datetime.timedelta(days=days)).isoformat()

        async def _list(access_token: str) -> list:
            return await gymsuit.get_workouts(access_token, from_date)

        return await _with_gymsuit(settings, store, gymsuit, email, _list)

    @mcp.tool(
        description=(
            "Delete one workout the caller logged through this server, by the "
            "external_id returned from log_workout."
        )
    )
    async def delete_workout_entry(external_id: str) -> dict:
        email = _require_email()
        if not external_id:
            raise ValueError("external_id is required")

        async def _delete(access_token: str) -> None:
            await gymsuit.delete_workout(access_token, external_id)

        await _with_gymsuit(settings, store, gymsuit, email, _delete)
        return {"deleted": external_id}

    @mcp.tool(
        description="Show who the current MCP login belongs to (GymSuit account)."
    )
    async def whoami() -> dict:
        email = _require_email()
        user = await store.get_gymsuit_user(email)
        if user is None:
            raise ValueError(f"No linked GymSuit account for {email}. Sign in again.")
        return {
            "email": user["email"],
            "first_name": user["first_name"],
            "last_name": user["last_name"],
            "member_id": user["member_id"],
            "gym_id": user["gym_id"],
            "gym_name": user["gym_name"],
        }

    return mcp
