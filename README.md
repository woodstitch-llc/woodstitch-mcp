# woodstitch-mcp

<!-- mcp-name: com.woodstitch/tts-human-eval -->

[![woodstitch-mcp MCP server](https://glama.ai/mcp/servers/woodstitch-llc/woodstitch-mcp/badges/score.svg)](https://glama.ai/mcp/servers/woodstitch-llc/woodstitch-mcp)

An [MCP](https://modelcontextprotocol.io) server for the [Woodstitch API](https://woodstitch.com/docs):
paid human listeners judge your text-to-speech audio in blinded studies, and your
agent gets a number back with a confidence interval.

Two tasks, and only two: **pairwise preference** (a listener hears two clips of the
same text and picks one, forced choice) and **human-vs-AI detection** (one clip,
human or AI, confidence 1–4). Not offered: MOS, CMOS, MUSHRA or any 1–5 scale.

## Hosted server (no install)

Woodstitch runs this server at **`https://api.woodstitch.com/mcp`** (streamable HTTP, OAuth sign-in).

- **Claude (web, desktop, Cowork):** Settings → Connectors → Add custom connector → paste the URL → sign in with Google, an emailed link, or your API key.
- **Claude Code:** `claude mcp add --transport http woodstitch https://api.woodstitch.com/mcp`
- **Other clients:** any MCP client with remote HTTP support; send `Authorization: Bearer ws_live_...` if it doesn't do OAuth.

The hosted server has no file-upload tool (it can't read your disk): pass audio as public URLs, or upload with `POST /v1/files` first.

## Install (local)

Get an API key at <https://woodstitch.com/app/api-keys>, then:

**Claude Code**

```bash
claude mcp add woodstitch -e WOODSTITCH_API_KEY=ws_live_... -- uvx woodstitch-mcp
```

**Claude Desktop / Cursor / any MCP client** (`mcpServers` entry):

```json
{
  "woodstitch": {
    "command": "uvx",
    "args": ["woodstitch-mcp"],
    "env": {"WOODSTITCH_API_KEY": "ws_live_..."}
  }
}
```

`pipx run woodstitch-mcp` or `pip install woodstitch-mcp && woodstitch-mcp` work too.
Requires Python 3.10+.

**Claude Code users:** the [Woodstitch plugin](https://github.com/woodstitch-llc/claude-plugin) bundles this server
with a skill that knows when and how to run a listening test:
`/plugin marketplace add woodstitch-llc/claude-plugin` then `/plugin install tts-human-eval@woodstitch`.

## Tools

| Tool | What it does | Money |
|---|---|---|
| `woodstitch_templates` | What is measured and what is not (no key needed) | – |
| `woodstitch_pricing` | Rate card and worked examples (no key needed) | – |
| `woodstitch_account` | Balance and spend | – |
| `woodstitch_upload_files` | Upload local audio, get file ids | – |
| `woodstitch_create_eval` | Create and **price** a study; `dry_run` to price only | **charges nothing** |
| `woodstitch_start_eval` | Start the study | **spends money** |
| `woodstitch_get_eval` | Progress and provisional score | – |
| `woodstitch_get_results` | Final numbers | – |
| `woodstitch_export` | Every judgement as rows (json or csv, optionally to a file) | – |
| `woodstitch_cancel_eval` | Stop early, pay only for work done | – |
| `woodstitch_list_evals`, `woodstitch_list_files`, `woodstitch_delete_file` | housekeeping | – |

## Safeguards built in

- `woodstitch_start_eval` requires `user_confirmed_amount_usd`, the quoted total the user agreed
  to, and sends it to the API as the hard ceiling `max_total_usd`. If the quote is higher than
  what the user confirmed, the API refuses (`over_max`) and nothing starts. An agent cannot start
  a study the user has not seen the price of.
- Every POST carries an `Idempotency-Key`, so a retried call never creates or starts a study twice.
- The server's instructions tell the model that interim numbers are provisional and that
  stopping early on a threshold is optional stopping.

## Typical session

1. `woodstitch_upload_files(["a/001.wav", "b/001.wav", ...])` or use public URLs.
2. `woodstitch_create_eval(pairs=[{"id":"001","a":"file_…","b":"file_…","passage":"001","system_a":"base","system_b":"candidate"}, …], ratings_per_pair=5)` → quote, nothing charged.
3. Show the user the total. On yes: `woodstitch_start_eval(eval_id, user_confirmed_amount_usd=<total>)`.
4. `woodstitch_get_eval(eval_id)` now and then; first judgements usually land within minutes.
5. `woodstitch_get_results(eval_id)` when `status` is `completed`; `woodstitch_export` for the rows.

Method, listener pay and controls: <https://woodstitch.com/research/methodology>.
Machine-readable API spec: <https://woodstitch.com/openapi.json>.

## Development

```bash
uv venv && . .venv/bin/activate && uv pip install -e .
WOODSTITCH_API_KEY=ws_live_... woodstitch-mcp        # stdio server
```

MIT © Woodstitch LLC
