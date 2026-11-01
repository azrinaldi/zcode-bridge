# AGENTS.md: AI Agent Playbook for `zcode-bridge`

Instructions for AI coding agents working on this bridge. The prose design
notes live in `README.md`; this file is the operational rulebook.

---

## 1. Critical Rules (Read First)

1. **Plan lane only, no signing.** Model traffic goes to
   `https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages` with
   `Authorization: Bearer <plan JWT>` and NO `X-Client-Sig` / `X-Client-Pow` /
   `X-App-Id` / `X-Zcode-Authorization`. Signed requests route to the paid
   lane and fail `429 1113` even when the plan balance is full. Do not "fix"
   this by re-adding signing headers to the plan path.
2. **The 3-block identity system is a gate, not a style choice.** Every
   upstream body must carry exactly three `system` blocks: `cliPrefix`
   verbatim, the canonical stable text byte-exact (leading `\n` included),
   then the client's own prompt. Wrong shape = `405 3012` regardless of
   headers. Build it only via `systemprompt.BuildSystem()`; never hand-copy
   the asset text into code. The asset is **client-version-tied**: if the
   desktop app updates and 3012 appears, re-capture the blocks from a live
   request and refresh `internal/systemprompt/identity_system.json` (and
   `identity.ResolveAppVersion`'s default).
3. **Model ids are lowercase.** `GLM-5.3-Flash` reaches the origin and gets
   an ALB 502; `glm-5.3-flash` answers 200. `models.NormalizeModel`
   enforces this — route all client model names through it.
4. **The plan JWT has no `exp`.** Claims are `{user_id, token_version, sub,
   iat}` only - a valid token does not expire on its own. Do not add expiry
   heuristics. Credential order (`auth.ResolvePlanJWT`): explicit argument
   -> `ZCODE_PLAN_JWT` env -> `plan-jwt.json` -> accounts store written by
   `zcode-bridge login` -> the desktop store
   (`~/.zcode/v2/credentials.json`, AES-256-GCM, see `auth.DesktopStoreJWT`)
   when one exists. On 401: a stored account gets ONE best-effort
   refresh-token grant, then the next account; the desktop fallback re-reads
   the store (the app rotating the token underneath us is the normal case).
5. **Loopback only, zero dependencies.** `HOST` defaults to `127.0.0.1`;
   Go standard library only; no `go get`. Port default `20131`
   (20129/20130/20133/20134/43095 are taken by sibling bridges/routers).
6. **Control-plane headers differ from LLM headers.** `billing/balance`
   requires `X-Device-Mid` (UUID) and answers `3001` without it; sending the
   control face to `billing/current` returns an EMPTY payload (verified
   2026-10-30), so `current` must use bare auth headers. Use
   `identity.BuildControlHeaders()` / `bareAuth` in `quota` accordingly.
7. **Never print the JWT or store secrets to stdout/logs.** Report lengths,
   suffixes, or `iat` only (see `/health`).

## 2. Concurrency Reality

The gateway meters in-flight requests per account, shared with the desktop
app: `429 3008` (user) / `3009` (model) are **transient**, not quota
exhaustion. The bridge serializes its own upstream calls through a single
lane (`transport.WithLane`) and retries with exponential backoff
(`ZCODE_MAX_ATTEMPTS`, `ZCODE_RETRY_BASE_MS`). A test failing with 3008/3009
while the desktop app is chatting is expected - re-run, don't "fix" code.

## 3. Running & Testing

```bash
go build -o zcode-bridge ./cmd/zcode-bridge
./zcode-bridge              # http://127.0.0.1:20131 (loopback default)
go test ./...               # end-to-end checks vs a stubbed balance-first gateway
```

Live matrix after any transport/identity change (in this order):
`/health` (planJwt present, deviceMid set) -> `/v1/quota` (`source: balance`,
`errors: []`) -> `/v1/models` (summed grants) -> one non-stream chat -> one
stream chat -> `/v1/messages` stream -> tool round-trip with follow-up
`tool_result`. All on lowercase ids.

## 4. Error Taxonomy (gateway `code` field)

| code | real meaning | right action |
|---|---|---|
| 3012 | identity-block/prompt-shape rejection | fix `system` shape via `BuildSystem`; only if shape is right and it persists, the account is throttled - wait |
| 1113 | paid lane + no balance | signing headers leaked into the plan request; remove them |
| 3008 | account in-flight (desktop app busy) | transient; the lane retry handles it |
| 3009 | model in-flight | transient; retry |
| 3001 | parameter error | control call missing UUID `X-Device-Mid`, or `current` called with the control header face |

## 5. Package Responsibilities

| Package | Owns |
|---|---|
| `cmd/zcode-bridge` | serve + `login` subcommands, background refresh ticker |
| `internal/server` | routes, dialect dispatch, `SessionKeyFor` affinity, OpenAI chunk translation (tool indexes remapped from Anthropic block indexes) |
| `internal/transport` | one upstream lane: `ShapePlanBody`, bearer auth, 401 refresh then re-read, transient retry with backoff, serialized `WithLane`; request cancel lives until the response body closes (`cancelBody`) |
| `internal/systemprompt` | the 3-block builder, derived stable `session_<32hex>` per conversation, `metadata.user_id` |
| `internal/identity` | g6n LLM header face (no device mid), TV control face (with `X-Device-Mid`), printable-ASCII gate |
| `internal/quota` | `balance`-first merge, `current` fallback with bare headers, `ByModel` |
| `internal/models` | lowercase canonical ids, OpenAI<->Anthropic translation incl. `role:"tool"` -> `tool_result` |
| `internal/auth` | JWT resolution order, desktop store decryption, device flow |
| `internal/accounts` | multi-account ring: upsert/list/usable, cooldowns, needsReauth, refresh |

## 6. Capturing Fresh Identity Blocks (after an app update)

1. Run the desktop app through a local MITM (the CA it trusts:
   `~/.zcode/v2/certs/zcode-network-ca.pem`), make one normal chat turn.
2. From the captured `zcode-plan/anthropic/v1/messages` request, take the
   exact `system` array blocks 1-2 and the `sdkUserAgent` header, refresh
   `internal/systemprompt/identity_system.json`, bump the app version
   default in `internal/identity`.
3. **Sanitize before committing**: the capture rides one real session, so
   strip anything session-specific (home paths, ids) from the stable text.
   The gateway validates the shape, not those tokens (verified live: a
   sanitized path still passes, personal paths leak otherwise).
4. `go test ./...` must stay green, then run the live matrix in section 3.
