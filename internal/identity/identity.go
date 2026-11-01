// Package identity builds the desktop client's companion headers, two faces.
//
// LLM face (bundle g6n): HTTP-Referer, User-Agent (+ ai-sdk suffix),
// [X-ZCode-App-Version], X-Title, X-Release-Channel, X-Client-Language,
// X-Client-Timezone, X-ZCode-Agent, [X-Platform], X-Os-Category,
// [X-Os-Version]. NO X-Device-Mid here.
//
// Control face (bundle TV, endpoint routing/billing): the same set PLUS
// X-Device-Mid (a UUID). GET /api/v1/zcode-plan/billing/balance answers
// `3001 parameter error` without it — verified live 2026-10-30; `current`
// works either way.
//
// Header values are gated to printable ASCII (bundle fio): anything else is
// dropped rather than sent, because the gateway rejects non-ASCII header
// values outright.
package identity

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
)

var asciiPrintable = regexp.MustCompile(`^[\x20-\x7e]+$`)

// Printable gates a raw value: trimmed, non-empty, printable ASCII — else "".
func Printable(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" || !asciiPrintable.MatchString(v) {
		return ""
	}
	return v
}

func envOr(key, fallback string) string {
	if v := Printable(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func osCategory(platform string) string {
	switch platform {
	case "darwin":
		return "macos"
	case "windows":
		return "windows"
	default:
		return "linux"
	}
}

func resolveClientLanguage() string {
	if v := Printable(os.Getenv("ZCODE_IDENTITY_CLIENT_LANGUAGE")); v != "" {
		return v
	}
	// Go has no Intl; TZ-shaped locale probe. The gateway only needs a
	// printable value, not a real BCP-47 tag.
	return envOr("LANG", "unknown")
}

func resolveClientTimezone() string {
	if v := Printable(os.Getenv("ZCODE_IDENTITY_CLIENT_TIMEZONE")); v != "" {
		return v
	}
	// time.Local's name is "Local" without /etc/localtime; TZ wins when set.
	if tz := Printable(os.Getenv("TZ")); tz != "" {
		return tz
	}
	return "unknown"
}

func resolvePlatform() string {
	if v := Printable(os.Getenv("ZCODE_IDENTITY_PLATFORM")); v != "" {
		return v
	}
	return runtime.GOOS + "-" + runtime.GOARCH
}

// ResolveAppVersion mirrors the desktop client version the asset was
// captured against. Bump only together with the identity asset.
func ResolveAppVersion() string {
	return envOr("ZCODE_IDENTITY_APP_VERSION", "3.16.3")
}

// ResolveDeviceMid picks the billing device UUID: ZCODE_IDENTITY_DEVICE_MID
// first, then the desktop client's own telemetry state. The gateway
// uuid.parse's the value — it must look like a UUID.
func ResolveDeviceMid() string {
	return Printable(os.Getenv("ZCODE_IDENTITY_DEVICE_MID"))
}

// LLMHeaderOpts carries the per-request correlation ids the LLM face needs.
type LLMHeaderOpts struct {
	SessionID   string
	RequestID   string
	TraceID     string
	QueryID     string
	SessionType string
	QuerySource string
}

// BuildLLMHeaders builds the plan-lane request headers (no device mid).
// anthropicVersion/anthropicBeta come from the identity asset.
func BuildLLMHeaders(anthropicVersion, anthropicBeta string, o LLMHeaderOpts) map[string]string {
	h := map[string]string{
		"http-referer":          "https://zcode.z.ai",
		"user-agent":            fmt.Sprintf("%s", Printable(os.Getenv("ZCODE_SDK_USER_AGENT"))),
		"x-title":               "Z Code@electron",
		"x-release-channel":     envOr("ZCODE_IDENTITY_RELEASE_CHANNEL", "production"),
		"x-client-language":     resolveClientLanguage(),
		"x-client-timezone":     resolveClientTimezone(),
		"x-zcode-agent":         "glm",
		"x-platform":            resolvePlatform(),
		"x-os-category":         osCategory(runtime.GOOS),
		"x-os-version":          envOr("ZCODE_IDENTITY_OS_VERSION", "unknown"),
		"x-zcode-app-version":   ResolveAppVersion(),
		"anthropic-version":     anthropicVersion,
		"anthropic-beta":        anthropicBeta,
		"x-zcode-session-type":  "main",
		"x-zcode-query-source":  "main_turn",
	}
	if ua := h["user-agent"]; ua == "" {
		h["user-agent"] = fmt.Sprintf("ZCode/%s", ResolveAppVersion())
	}
	if o.SessionID != "" {
		h["x-session-id"] = o.SessionID
	}
	if o.RequestID != "" {
		h["x-request-id"] = o.RequestID
	}
	if o.TraceID != "" {
		h["x-zcode-trace-id"] = o.TraceID
	}
	if o.QueryID != "" {
		h["x-query-id"] = o.QueryID
	}
	if o.SessionType == "" {
		o.SessionType = "main"
	}
	h["x-zcode-session-type"] = o.SessionType
	if o.QuerySource == "" {
		o.QuerySource = "main_turn"
	}
	h["x-zcode-query-source"] = o.QuerySource
	return h
}

// BuildControlHeaders builds the billing/claim face: LLM face plus
// X-Device-Mid. Sending this face to billing/current empties its payload —
// the fallback there must use bare auth only.
func BuildControlHeaders(deviceMid string) map[string]string {
	h := map[string]string{
		"http-referer":        "https://zcode.z.ai",
		"user-agent":          fmt.Sprintf("ZCode/%s", ResolveAppVersion()),
		"x-title":             "Z Code@electron",
		"x-release-channel":   "production",
		"x-client-language":   resolveClientLanguage(),
		"x-client-timezone":   resolveClientTimezone(),
		"x-platform":          resolvePlatform(),
		"x-os-category":       osCategory(runtime.GOOS),
		"x-os-version":        envOr("ZCODE_IDENTITY_OS_VERSION", "unknown"),
		"x-zcode-app-version": ResolveAppVersion(),
		"content-type":        "application/json",
		"accept":              "application/json",
	}
	if mid := deviceMid; mid != "" {
		if Printable(mid) != "" {
			h["x-device-mid"] = mid
		}
	} else if mid := ResolveDeviceMid(); mid != "" {
		h["x-device-mid"] = mid
	}
	return h
}

// Platform resolves the x-platform identity value (os-arch by default).
func Platform() string { return resolvePlatform() }

// Origin is the inference/billing origin origin (no trailing slash).
func Origin() string {
	if v := Printable(os.Getenv("ZCODE_INFERENCE_ORIGIN")); v != "" {
		return v
	}
	return "https://zcode.z.ai"
}
