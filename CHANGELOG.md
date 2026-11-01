# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-01

First public release.

### Added

- `POST /v1/messages` (Anthropic) pass-through into the ZCode plan lane.
- `POST /v1/chat/completions` (OpenAI) with bidirectional translation,
  including SSE streaming (`chat.completion.chunk`, `reasoning_content`,
  remapped `tool_calls` indexes, `[DONE]`) and tool round-trips.
- `GET /v1/models` with live entitlement merging across plans and a static
  fallback when billing is unreachable.
- `GET /v1/quota` per-entitlement grant rows, balance-first with a
  `billing/current` fallback on bare auth headers.
- `GET /health` reporting lane, credential ring and device-mid state without
  exposing secrets.
- `login` device flow, account ring store (`0600`, multi-account rotation,
  cooldowns, `--label` / `--list` / `--set-default` / `--remove`), and a
  15-minute background refresh for tokens expiring within two hours.
- Three-block identity shaping from the embedded identity asset, derived
  per-conversation session ids, and lowercase model-id normalization.
- Serialized upstream lane with exponential backoff for transient
  `3008`/`3009` concurrency errors.
- Optional `ZCODE_BRIDGE_TOKEN` gate and opt-in `ZCODE_CORS_ORIGIN`.
- Prebuilt binaries for linux/darwin/windows on amd64/arm64.

[Unreleased]: https://github.com/azrinaldi/zcode-bridge/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/azrinaldi/zcode-bridge/releases/tag/v0.1.0
