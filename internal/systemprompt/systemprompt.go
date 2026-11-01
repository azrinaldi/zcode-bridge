// Package systemprompt builds the ZCode gateway's identity system blocks.
//
// The start-plan gateway (/api/v1/zcode-plan/anthropic/v1/messages) does
// content inspection on the `system` field. Live matrix 2026-10-30 (captured
// desktop request + replays):
//
//   - block 1 must be EXACTLY cliPrefix ("You are ZCode, an interactive
//     coding agent") — a merged single block or a prefix of it: 405/3012.
//   - block 2 must OPEN with the full canonical stable text (leading "\n"
//     included, captured on 3.16.3). Truncated/normalised copies of it, or
//     fabricated lookalikes, are refused.
//   - block 3 is UNCONSTRAINED: empty string, whitespace, or arbitrary client
//     instructions all pass. It carries the caller's own system prompt.
//   - cache_control: ephemeral sits on blocks 2 and 3 (captured shape); the
//     gateway tolerates its absence but the bridge mirrors the client.
//
// The asset is client-version-tied: on a 3012 after an app update, re-capture
// the blocks from a live desktop request and refresh identity_system.json.
package systemprompt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
)

//go:embed identity_system.json
var assetRaw []byte

// Asset mirrors the captured identity file (sanitized for publication).
type Asset struct {
	Source           string `json:"source"`
	CliPrefix        string `json:"cliPrefix"`
	StablePrefix     string `json:"stablePrefix"`
	AnthropicVersion string `json:"anthropicVersion"`
	AnthropicBeta    string `json:"anthropicBeta"`
	SDKUserAgent     string `json:"sdkUserAgent"`
}

var identity Asset

func init() {
	if err := json.Unmarshal(assetRaw, &identity); err != nil {
		panic("zcode-bridge: embedded identity asset is invalid: " + err.Error())
	}
	if len(identity.StablePrefix) < 1500 {
		panic("zcode-bridge: captured stable prefix is too short to satisfy the identity gate")
	}
}

// Captured returns the loaded identity asset.
func Captured() Asset { return identity }

// Block is one Anthropic system content block.
type Block struct {
	Type         string       `json:"type"`
	Text         string       `json:"text"`
	CacheControl *CachePolicy `json:"cache_control,omitempty"`
}

// CachePolicy mirrors Anthropic's prompt-cache marker.
type CachePolicy struct {
	Type string `json:"type"`
}

// NormalizeClientSystem joins client system blocks into one string;
// empty/absent input yields "".
func NormalizeClientSystem(system any) string {
	switch v := system.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			switch b := item.(type) {
			case string:
				if strings.TrimSpace(b) != "" {
					parts = append(parts, b)
				}
			case map[string]any:
				if t, ok := b["text"].(string); ok && strings.TrimSpace(t) != "" {
					parts = append(parts, t)
				}
			}
		}
		return strings.TrimSpace(strings.Join(parts, "\n\n"))
	default:
		return ""
	}
}

// BuildSystem builds the 3-block system array for one upstream request.
// clientSystem (string | block array | nil) becomes block 3 verbatim.
func BuildSystem(clientSystem any) []Block {
	dynamic := NormalizeClientSystem(clientSystem)
	block3 := ""
	if dynamic != "" {
		block3 = "\n\n" + dynamic
	}
	return []Block{
		{Type: "text", Text: identity.CliPrefix},
		{Type: "text", Text: identity.StablePrefix, CacheControl: &CachePolicy{Type: "ephemeral"}},
		{Type: "text", Text: block3, CacheControl: &CachePolicy{Type: "ephemeral"}},
	}
}

// SessionIDFor derives a stable per-conversation session id, `session_<32hex>`
// shaped like the desktop client's. Retries of one conversation reuse the id,
// which the gateway meters per session; a random id is used without a key.
func SessionIDFor(key, seed string) string {
	if key == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		return "session_" + hex.EncodeToString(b)
	}
	if seed == "" {
		seed = "zcode-bridge"
	}
	mac := hmac.New(sha256.New, []byte(seed))
	mac.Write([]byte{'\x00'})
	mac.Write([]byte(key))
	return "session_" + hex.EncodeToString(mac.Sum(nil))[:32]
}

// MetadataUserID builds Anthropic metadata.user_id — a JSON string in the
// client: {"device_id","account_uuid","session_id"}. The gateway reads the
// device id for attribution; keep it a UUID like the real one.
func MetadataUserID(deviceID, sessionID, accountUUID string) string {
	b, _ := json.Marshal(map[string]string{
		"device_id":    deviceID,
		"account_uuid": accountUUID,
		"session_id":   sessionID,
	})
	return string(b)
}

// ForceThinking reports whether every upstream body should carry
// thinking:{type:"enabled"} (ZCODE_FORCE_THINKING=1).
func ForceThinking() bool { return os.Getenv("ZCODE_FORCE_THINKING") == "1" }
