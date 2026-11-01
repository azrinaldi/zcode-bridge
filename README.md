# zcode-bridge

OpenAI- and Anthropic-compatible HTTP front end for the **ZCode start-plan
quota** (GLM-5.3 / GLM-5.3-Flash). Point any harness that speaks
`/v1/messages` or `/v1/chat/completions` at it, and calls are metered against
the plan grants the account already owns (`ZCODE WEEKEND BUILD`, `ZCode Start
Plan`) — the same quota the ZCode desktop panel shows. Nothing bypasses
billing: the bridge *is* a genuine plan-lane client, reusing the desktop
login's own credential.

Single static Go binary, standard library only, no runtime dependencies.

## Quick start

```sh
go build -o zcode-bridge ./cmd/zcode-bridge
./zcode-bridge login            # opens the device flow; approve in a browser
./zcode-bridge                  # serves on 127.0.0.1:20131
```

`login` prints an approval URL; open it in any browser signed in to Z.ai
(the desktop app is not required). The resulting plan JWT + refresh token is
stored in `data/accounts.json` (mode `0600`). Repeat `login --label work`
per account; use `login --list`, `login --set-default <id>`,
`login --remove <id>` to manage the ring.

## Connect anything

OpenAI wire format (any SDK: set base URL to `http://127.0.0.1:20131/v1`,
api key to whatever / your bridge token):

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:20131/v1", api_key="bridge")
r = client.chat.completions.create(
    model="glm-5.3-flash",
    messages=[{"role": "user", "content": "hello"}],
)
```

Anthropic wire format (Claude Code, Aider, …: base URL
`http://127.0.0.1:20131`, auth token ignored / bridge token):

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:20131
export ANTHROPIC_AUTH_TOKEN=bridge
```

curl:

```sh
curl -s http://127.0.0.1:20131/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"glm-5.3-flash","messages":[{"role":"user","content":"ping"}]}'
```

## Routes

| Route | Dialect | Notes |
|---|---|---|
| `POST /v1/messages` | Anthropic | pass-through into the plan lane |
| `POST /v1/chat/completions` | OpenAI | translated both ways, incl. streaming + tools |
| `GET /v1/models` | — | live entitlements merged across plans (static fallback when billing is down) |
| `GET /v1/quota` | — | per-entitlement grant rows (balance-first) |
| `GET /health` | — | lane, credential ring, device-mid state |

Streaming: Anthropic callers get the upstream SSE stream untouched; OpenAI
callers get `chat.completion.chunk` frames translated from it (`reasoning_content`
carries thinking deltas, tool calls are remapped onto OpenAI's `tool_calls`
indexing, terminated with `[DONE]`).

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `PORT` / `HOST` | `20131` / `127.0.0.1` | listen address (keep it loopback unless you front it with auth) |
| `ZCODE_BRIDGE_TOKEN` | *(unset = open)* | require `Authorization: Bearer` or `x-api-key` on inference routes |
| `ZCODE_PLAN_JWT` | — | explicit plan JWT (highest-priority credential) |
| `ZCODE_PLAN_JWT_FILE` | `./plan-jwt.json` | single-token fallback file |
| `ZCODE_ACCOUNTS_FILE` | `data/accounts.json` | account ring store (0600) |
| `ZCODE_IDENTITY_DEVICE_MID` | auto (per-account UUID from login; random on legacy resolve) | UUID for billing/control calls; without it `/v1/quota` answers `3001` |
| `ZCODE_SESSION_SEED` | `zcode-bridge` | HMAC seed for derived session ids |
| `ZCODE_IDENTITY_CLIENT_LANGUAGE` / `_TIMEZONE` / `_PLATFORM` | auto | identity header overrides |
| `ZCODE_INFERENCE_ORIGIN` | `https://zcode.z.ai` | plan-lane origin (tests point this at a stub) |
| `ZCODE_OAUTH_ORIGIN` | `https://zcode.z.ai` | OAuth/token origin |
| `ZCODE_MAX_ATTEMPTS` | `3` | transient-retry budget per request |
| `ZCODE_RETRY_BASE_MS` | `1500` | exponential backoff base (3009/429/5xx) |
| `ZCODE_UPSTREAM_TIMEOUT_MS` | `300000` | hard upstream deadline |
| `ZCODE_LANE_WIDTH` | `1` | concurrent in-flight upstream requests (the plan lane meters serially; keep 1) |
| `ZCODE_ACCOUNT_COOLDOWN_MS` | `900000` | cooldown after a switchable error (1113/429) |
| `ZCODE_REFRESH_INTERVAL_MS` | `900000` | background refresh check period |
| `ZCODE_FORCE_THINKING` | *(off)* | `1` = force thinking on every request |
| `ZCODE_CORS_ORIGIN` | *(off)* | `*` or comma list; opt-in browser support |
| `ZCODE_SDK_USER_AGENT` | auto | override the SDK user-agent face |

## Lane rules (verified against production)

- The plan lane wants **exactly three system blocks**: the CLI prefix
  verbatim, the canonical stable identity prefix (byte-exact, with
  `cache_control: ephemeral`), then the client's own system text. The bridge
  shapes this from the embedded identity asset — send a client system
  normally, it lands in block 3.
- **No signing headers** (`x-client-sig` etc.) on the plan lane; the lane is
  already authenticated by the plan JWT and signed requests get `1113`.
- Model ids are **case-sensitive lowercase**: `glm-5.3-flash`, not
  `GLM-5.3-Flash`. The bridge normalizes automatically.
- `billing/balance` needs a UUID `X-Device-Mid` or it answers `3001`;
  `billing/current` must use bare auth (control headers empty its payload).
- Errors inside HTTP 200: the `{code,msg,logid}` envelope; `3012` = identity
  gate, `3008` = user concurrency, `3009` = model concurrency (transient,
  retried with backoff), `1113` = grant spent (rotates accounts when a ring
  exists).

## Multi-account

Requests try the default account first; a switchable error (grant spent,
revoked, concurrency) parks that account (cooldown → re-auth on 401/403) and
rotates to the next healthy one in the same request. Pin one account per
request with `?account=<id>` (or the `x-zcode-account` header) to skip
rotation. A 401 triggers one best-effort refresh against the token endpoint
before rotating. Background refresh runs every 15 minutes for tokens
expiring within 2 hours.

## Files

| Path | Purpose |
|---|---|
| `cmd/zcode-bridge` | entry point: serve + login subcommand |
| `internal/server` | HTTP routes, SSE translation, session affinity |
| `internal/transport` | plan-lane client: shaping, rotation, retries |
| `internal/models` | OpenAI ↔ Anthropic translation |
| `internal/quota` | billing readout + per-model merge |
| `internal/accounts` | account ring store (0600), cooldowns, refresh |
| `internal/auth` | device flow, token refresh, credential resolve chain |
| `internal/identity` | identity/telemetry headers, device mid, app version |
| `internal/systemprompt` | embedded identity asset + 3-block shaping |

## Testing

```sh
go test ./...            # end-to-end suite against a stub gateway
go test ./internal/server/ -race
```

## Deploying

Keep it on loopback behind your own auth, or set `ZCODE_BRIDGE_TOKEN` and
bind a private interface. systemd unit:

```ini
[Unit]
Description=zcode-bridge
After=network-online.target

[Service]
ExecStart=/usr/local/bin/zcode-bridge
Environment=ZCODE_BRIDGE_TOKEN=change-me
Restart=on-failure
User=you

[Install]
WantedBy=multi-user.target
```

## License

MIT — see [LICENSE](LICENSE).
