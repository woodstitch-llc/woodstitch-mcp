"""End-to-end smoke test: spawn the server over stdio as a real MCP client would, list the
tools, and exercise the read-only ones plus a dry-run create. With a zero-spend key the
start call must be refused by the API (spend_cap) and the guard must refuse a wrong amount.

    WOODSTITCH_API_KEY=... python tests/smoke.py [path/to/audio1 path/to/audio2]
"""
import asyncio, json, os, sys, time
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession

PUB_A = "https://woodstitch.com/research/audio/audiobook/eleven_v4__q01.mp3"
PUB_B = "https://woodstitch.com/research/audio/audiobook/qwen_31_flash__q01.mp3"

def is_err(res):
    return bool(getattr(res, 'is_error', getattr(res, 'isError', False)))

def text(res):
    out = []
    for c in res.content:
        if getattr(c, "text", None):
            out.append(c.text)
    return "\n".join(out)

async def call(s, tool, **args):
    r = await s.call_tool(tool, args)
    t = text(r)
    try:
        d = json.loads(t)
    except Exception:
        d = t
    print(f"\n== {tool}({', '.join(f'{k}=...' for k in args)}) {'ERROR' if is_err(r) else 'ok'}")
    print(json.dumps(d, indent=1)[:900] if not isinstance(d, str) else d[:900])
    return r, d

async def main():
    params = StdioServerParameters(command=sys.executable, args=["-m", "woodstitch_mcp.server"], env={**os.environ})
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = await s.list_tools()
            print("tools:", [t.name for t in tools.tools])
            assert len(tools.tools) == 13, len(tools.tools)
            await call(s, "woodstitch_templates")
            await call(s, "woodstitch_pricing")
            await call(s, "woodstitch_account")
            pairs = [{"id": "q01", "a": PUB_A, "b": PUB_B, "passage": "q01", "system_a": "eleven_v4", "system_b": "qwen_31_flash"}]
            _, dry = await call(s, "woodstitch_create_eval", pairs=pairs, ratings_per_pair=3, name="mcp smoke (dry)", dry_run=True)
            _, tpl = await call(s, "woodstitch_templates")
            assert [t["id"] for t in tpl["templates"]] == ["tts_preference.v1", "tts_detect.v1", "tts_mos.v1", "tts_cmos.v1"], tpl
            assert "not_offered" not in tpl
            _, cd = await call(s, "woodstitch_create_eval", template="tts_cmos.v1", pairs=pairs, ratings_per_pair=3, name="mcp smoke cmos (dry)", dry_run=True)
            assert cd["quote"]["total_usd"] == dry["quote"]["total_usd"], (cd, dry)   # CMOS priced exactly like preference
            clips = [{"id": "m-a", "audio": PUB_A, "system": "eleven_v4", "passage": "q01"},
                     {"id": "m-b", "audio": PUB_B, "system": "qwen_31_flash", "passage": "q01"}]
            _, md = await call(s, "woodstitch_create_eval", template="tts_mos.v1", clips=clips, ratings_per_clip=3, name="mcp smoke mos (dry)", dry_run=True)
            assert md.get("dry_run") is True and md["judgements"] == 6, md
            r, _ = await call(s, "woodstitch_create_eval", template="tts_mos.v1", pairs=pairs, dry_run=True)
            assert is_err(r), "MOS without clips must be refused locally"
            if len(sys.argv) >= 3:
                _, up = await call(s, "woodstitch_upload_files", paths=sys.argv[1:3])
                ids = [f["id"] for f in up["files"]]
                pairs2 = [{"id": "local-1", "a": ids[0], "b": ids[1], "passage": "p1"}]
                _, created = await call(s, "woodstitch_create_eval", pairs=pairs2, ratings_per_pair=3, name="mcp smoke (real create, never started)", question=f"Which audio sample do you prefer? (smoke {int(time.time())})")
                eid = created.get("eval_id")
                if eid:
                    await call(s, "woodstitch_get_eval", eval_id=eid)
                    total = created["quote"]["total_usd"]
                    r1, _ = await call(s, "woodstitch_start_eval", eval_id=eid, user_confirmed_amount_usd=round(total - 0.5, 2))
                    assert is_err(r1), "API should refuse (over_max) when the confirmed amount is below the quote"
                    r2, _ = await call(s, "woodstitch_start_eval", eval_id=eid, user_confirmed_amount_usd=total)
                    print("start with the confirmed amount ->", "refused by API (expected: spend_cap on the zero-spend key)" if is_err(r2) else "STARTED (unexpected!)")
                    await call(s, "woodstitch_cancel_eval", eval_id=eid)  # confirm missing -> guard error
                    await call(s, "woodstitch_cancel_eval", eval_id=eid, confirm=True)
                    await call(s, "woodstitch_list_evals")
            print("\nsmoke test finished")

asyncio.run(main())
