"""MCP server for the Woodstitch API (https://woodstitch.com/docs).

Runs over stdio. Every tool is a thin, typed wrapper over one API call; the
server adds the two things an agent must not get wrong: nothing is started
without the user confirming the quoted amount, and every POST carries an
Idempotency-Key so a retry never buys a study twice.

    WOODSTITCH_API_KEY=ws_live_...  woodstitch-mcp

Works with mcp 1.x (FastMCP) and 2.x (MCPServer).
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Optional

import httpx

try:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore

try:
    from mcp.types import ToolAnnotations
except Exception:  # pragma: no cover
    ToolAnnotations = None  # type: ignore

from . import __version__

BASE_URL = os.environ.get("WOODSTITCH_BASE_URL", "https://api.woodstitch.com/v1").rstrip("/")
UA = f"woodstitch-mcp/{__version__}"

INSTRUCTIONS = """Woodstitch: paid human listeners judge text-to-speech audio in blinded studies.
Two tasks only: pairwise preference (two clips, forced choice) and human-vs-AI detection
(one clip, human or AI, confidence 1-4). Not offered: MOS, CMOS, MUSHRA or any 1-5 scale.

Flow: woodstitch_upload_files (or public URLs) -> woodstitch_create_eval (free quote;
dry_run=true to price without storing) -> show the quote to the user -> woodstitch_start_eval
(SPENDS MONEY) -> woodstitch_get_eval to poll (humans take minutes to days) ->
woodstitch_get_results / woodstitch_export.

Rules: never call woodstitch_start_eval until the user has seen the quoted total and said
yes; the tool requires you to pass that confirmed amount and a hard spending ceiling.
Polling is cheap, but interim numbers are provisional: stopping early because a number
crossed a threshold is optional stopping and inflates false positives. Use the same audio
format and bitrate on both sides of a pair. Give each pair a passage id and system labels
so no listener hears one system often enough to recognise it."""

mcp = _Server(
    name="woodstitch",
    instructions=INSTRUCTIONS,
    version=__version__,
)


# ----------------------------------------------------------------------------- http
# ToolError is the one exception type whose message the SDK passes through to the model;
# anything else is reported as a bare "Error executing tool". The API's error code and hint
# are exactly what the model needs to recover, so they must travel in that message.
try:  # mcp 2.x
    from mcp.server.mcpserver.exceptions import ToolError as _ToolError
except ImportError:  # mcp 1.x
    try:
        from mcp.server.fastmcp.exceptions import ToolError as _ToolError  # type: ignore
    except ImportError:  # pragma: no cover
        _ToolError = Exception  # type: ignore


class WoodstitchError(_ToolError):  # type: ignore[misc]
    pass


def _key(required: bool = True) -> Optional[str]:
    k = os.environ.get("WOODSTITCH_API_KEY", "").strip()
    if not k and required:
        raise WoodstitchError(
            "WOODSTITCH_API_KEY is not set. Create a key at https://woodstitch.com/app/api-keys "
            "and start the server with that variable in its environment."
        )
    return k or None


def _client(auth: bool = True) -> httpx.Client:
    headers = {"User-Agent": UA, "Accept": "application/json"}
    k = _key(required=auth)
    if k:
        headers["Authorization"] = f"Bearer {k}"
    return httpx.Client(base_url=BASE_URL, headers=headers, timeout=httpx.Timeout(300.0, connect=30.0))


def _unwrap(r: httpx.Response) -> Any:
    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text[:2000]}
    if r.status_code >= 400:
        err = body.get("error") if isinstance(body, dict) else None
        if isinstance(err, dict):
            msg = f"{err.get('code', 'error')} (HTTP {r.status_code}): {err.get('message', '')}"
            if err.get("hint"):
                msg += f" Hint: {err['hint']}"
            raise WoodstitchError(msg)
        raise WoodstitchError(f"HTTP {r.status_code}: {json.dumps(body)[:1000]}")
    return body


def _get(path: str, auth: bool = True, **params: Any) -> Any:
    with _client(auth) as c:
        return _unwrap(c.get(path, params={k: v for k, v in params.items() if v is not None}))


def _post(path: str, body: Optional[dict] = None, idempotency_key: Optional[str] = None) -> Any:
    headers = {"Idempotency-Key": idempotency_key or str(uuid.uuid4())}
    with _client() as c:
        return _unwrap(c.post(path, json=body or {}, headers=headers))


def _ann(read_only: bool = False, destructive: bool = False, idempotent: bool = False):
    if ToolAnnotations is None:
        return None
    return ToolAnnotations(readOnlyHint=read_only, destructiveHint=destructive, idempotentHint=idempotent, openWorldHint=True)


# ----------------------------------------------------------------------------- public
@mcp.tool(annotations=_ann(read_only=True), description=(
    "What Woodstitch measures: the two templates (tts_preference.v1: two clips, forced choice; "
    "tts_detect.v1: one clip, human or AI + confidence), their inputs and metrics, and what is NOT "
    "offered (MOS, CMOS, MUSHRA, any 1-5 scale). No API key needed."))
def woodstitch_templates() -> dict:
    return _get("/templates", auth=False)


@mcp.tool(annotations=_ann(read_only=True), description=(
    "Rate card: USD per hour of audio a listener hears, priced per judgement from the measured "
    "duration of your clips, with worked examples and limits. No API key needed."))
def woodstitch_pricing() -> dict:
    return _get("/pricing", auth=False)


# ----------------------------------------------------------------------------- account
@mcp.tool(annotations=_ann(read_only=True), description="Account balance and spend for the configured API key.")
def woodstitch_account() -> dict:
    return _get("/account")


@mcp.tool(annotations=_ann(read_only=True), description="Your last 50 evaluations with status and progress.")
def woodstitch_list_evals() -> dict:
    return _get("/evals")


# ----------------------------------------------------------------------------- files
@mcp.tool(annotations=_ann(idempotent=True), description=(
    "Upload audio files from the local disk (wav, mp3, flac, ogg, m4a; 0.5-120 s each, 50 MB per file, "
    "up to 100 files per call). Returns file ids, measured durations and formats, in the order sent. "
    "Use an id anywhere woodstitch_create_eval takes an audio reference. Re-uploading the same bytes "
    "is harmless (content-addressed)."))
def woodstitch_upload_files(paths: list[str]) -> dict:
    if not paths:
        raise WoodstitchError("paths is empty")
    if len(paths) > 100:
        raise WoodstitchError("at most 100 files per call; split the list")
    files = []
    handles = []
    try:
        for p in paths:
            fp = Path(p).expanduser()
            if not fp.is_file():
                raise WoodstitchError(f"not a file: {p}")
            h = fp.open("rb")
            handles.append(h)
            files.append(("file[]", (fp.name, h, "application/octet-stream")))
        with _client() as c:
            return _unwrap(c.post("/files", files=files))
    finally:
        for h in handles:
            h.close()


@mcp.tool(annotations=_ann(read_only=True), description="List your uploaded files, newest first.")
def woodstitch_list_files() -> dict:
    return _get("/files")


@mcp.tool(annotations=_ann(destructive=True), description=(
    "Delete one upload from your account by file id. Studies that already used the file keep their copy."))
def woodstitch_delete_file(file_id: str) -> dict:
    with _client() as c:
        return _unwrap(c.delete(f"/files/{file_id}"))


# ----------------------------------------------------------------------------- evals
@mcp.tool(annotations=_ann(idempotent=True), description=(
    "Create and PRICE an evaluation. Charges nothing. Resolves every clip (file id or public URL), "
    "validates it, measures duration and returns a quote with per-pair prices, warnings and the "
    "compiled design. Set dry_run=true to price without storing anything (no eval_id). "
    "Preference: pass `pairs` as [{id, a, b, system_a?, system_b?, passage?, speaker?}] where a/b are "
    "file ids or URLs rendering the SAME text; sides are shown to listeners in random order. "
    "Detection: pass `clips` as [{id, audio, truth: 'human'|'ai', source, speaker, passage, "
    "duration_bucket?}] and include real human recordings of the same passages as the baseline. "
    "`per_participant` = {max_judgements, unique_by: [...], max_per: {...}} limits what one listener "
    "hears; for a multi-system comparison use unique_by ['passage'] and max_per {'system': N}. "
    "ALWAYS show the returned quote total to the user before starting."))
def woodstitch_create_eval(
    pairs: Optional[list[dict]] = None,
    clips: Optional[list[dict]] = None,
    template: str = "tts_preference.v1",
    ratings_per_pair: Optional[int] = None,
    ratings_per_clip: Optional[int] = None,
    per_participant: Optional[dict] = None,
    allocation: Optional[dict] = None,
    question: Optional[str] = None,
    name: Optional[str] = None,
    dry_run: bool = False,
    idempotency_key: Optional[str] = None,
) -> dict:
    if template not in ("tts_preference.v1", "tts_detect.v1"):
        raise WoodstitchError("template must be tts_preference.v1 or tts_detect.v1")
    if template == "tts_preference.v1" and not pairs:
        raise WoodstitchError("preference studies need `pairs`")
    if template == "tts_detect.v1" and not clips:
        raise WoodstitchError("detection studies need `clips`")
    body: dict[str, Any] = {"template": template, "dry_run": bool(dry_run)}
    for k, v in (("pairs", pairs), ("clips", clips), ("ratings_per_pair", ratings_per_pair),
                 ("ratings_per_clip", ratings_per_clip), ("per_participant", per_participant),
                 ("allocation", allocation), ("question", question), ("name", name)):
        if v is not None:
            body[k] = v
    out = _post("/evals", body, idempotency_key)
    if isinstance(out, dict):
        q = (out.get("quote") or {}).get("total_usd")
        out["_next_step"] = (
            "Nothing has been charged. "
            + (f"Show the user the quoted total of ${q:.2f} and ask whether to start. " if isinstance(q, (int, float)) else "")
            + ("This was a dry run: nothing was stored; create again without dry_run to get an eval_id."
               if dry_run else "If they say yes, call woodstitch_start_eval with eval_id, that exact amount as "
               "user_confirmed_amount_usd, and a max_total_usd ceiling.")
        )
    return out


@mcp.tool(annotations=_ann(), description=(
    "START an evaluation. THIS SPENDS REAL MONEY and cannot be undone once listeners begin. "
    "Only call it after the user has seen the quote total returned by woodstitch_create_eval and "
    "explicitly agreed. Pass that total as user_confirmed_amount_usd: it is sent to the API as the "
    "hard spending ceiling (max_total_usd), so if the current quote is higher than what the user "
    "confirmed the API refuses with over_max and nothing starts. Billing is metered from the first "
    "judgement; a study pauses rather than overspends if the balance runs out."))
def woodstitch_start_eval(
    eval_id: int,
    user_confirmed_amount_usd: float,
    quote_id: Optional[int] = None,
    idempotency_key: Optional[str] = None,
) -> dict:
    ceiling = float(user_confirmed_amount_usd)
    if not ceiling > 0:
        raise WoodstitchError("user_confirmed_amount_usd must be the positive quoted total the user agreed to")
    current = _get(f"/evals/{eval_id}")
    status = (current or {}).get("status")
    if status != "ready":
        raise WoodstitchError(f"evaluation {eval_id} is '{status}', not 'ready'; only a created, unstarted evaluation can be started")
    body: dict[str, Any] = {"max_total_usd": round(ceiling, 2)}
    if quote_id is not None:
        body["quote_id"] = int(quote_id)
    out = _post(f"/evals/{eval_id}/start", body, idempotency_key)
    if isinstance(out, dict):
        out["_note"] = (f"Started with a hard ceiling of ${ceiling:.2f}. Poll woodstitch_get_eval; first judgements "
                        "usually arrive within minutes, completion takes hours to days depending on size.")
    return out


@mcp.tool(annotations=_ann(read_only=True), description=(
    "Progress and live score for an evaluation: status, judgements done/target, pairs with data, "
    "provisional metrics, dashboard_url, and max_additional_charge_if_canceled_now_usd. Cheap to poll. "
    "Humans take minutes to days; do not sit in a tight loop. Interim numbers are provisional."))
def woodstitch_get_eval(eval_id: int) -> dict:
    return _get(f"/evals/{eval_id}")


@mcp.tool(annotations=_ann(read_only=True), description=(
    "Final numbers once the evaluation is completed (or canceled, then incomplete=true). "
    "Preference: human_pref/b_win_rate is the share of preference for your b side with a 95% CI; "
    "0.5 = indistinguishable. Detection: human_label_rate per source with two intervals: "
    "tested_stimuli (these files) and model (generalises over voices and passages; 3-4x wider; "
    "quote THIS one for any claim about a model). Returns not_ready while still running."))
def woodstitch_get_results(eval_id: int) -> dict:
    return _get(f"/evals/{eval_id}/results")


@mcp.tool(annotations=_ann(read_only=True), description=(
    "Every judgement as a row (pseudonymous rater, pair/clip id, source, speaker, passage, answer, "
    "confidence, time spent). format 'json' returns the rows; 'csv' returns CSV text. Pass save_to "
    "(a local path) to write the export to disk instead of returning it, which is better for large studies."))
def woodstitch_export(eval_id: int, format: str = "json", save_to: Optional[str] = None) -> dict:
    if format not in ("json", "csv"):
        raise WoodstitchError("format must be json or csv")
    with _client() as c:
        r = c.get(f"/evals/{eval_id}/export", params={"format": format})
        if r.status_code >= 400:
            _unwrap(r)
        text = r.text
    if save_to:
        p = Path(save_to).expanduser()
        p.write_text(text)
        return {"saved_to": str(p), "bytes": len(text.encode())}
    return {"format": format, "export": (json.loads(text) if format == "json" else text)}


@mcp.tool(annotations=_ann(destructive=True), description=(
    "Stop an evaluation early. Charges only for work already handed to listeners; anyone mid-task "
    "finishes and is paid. Check max_additional_charge_if_canceled_now_usd via woodstitch_get_eval "
    "first if the user wants that number. Requires confirm=true."))
def woodstitch_cancel_eval(eval_id: int, confirm: bool = False, idempotency_key: Optional[str] = None) -> dict:
    if not confirm:
        raise WoodstitchError("set confirm=true after the user has agreed to cancel")
    return _post(f"/evals/{eval_id}/cancel", {}, idempotency_key)


# ----------------------------------------------------------------------------- entry
def main() -> None:
    if "--version" in sys.argv:
        print(f"woodstitch-mcp {__version__}")
        return
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
