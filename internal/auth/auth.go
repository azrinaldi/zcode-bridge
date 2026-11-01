// Package auth handles credential acquisition for the bridge.
//
// The bridge spends the ZCode start-plan quota, and that lane needs exactly
// one credential: the plan JWT (Authorization: Bearer <jwt>), issued by the
// OAuth device flow. The JWT has no `exp` claim (claims are
// {user_id, token_version, sub, iat}), so "expired" here means only what the
// token itself claims — never guess. A 401 means the token was revoked
// (token_version bump): re-run login.
//
// Resolution order (ResolvePlanJWT): ZCODE_PLAN_JWT env -> plan-jwt.json ->
// the accounts store written by login -> the desktop client's own store
// (~/.zcode/v2/credentials.json) when one exists.
package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

// OAuthBase is the Z.ai OAuth endpoint origin. ZCODE_OAUTH_ORIGIN
// overrides it (tests stub the token endpoints).
var OAuthBase = envOr("ZCODE_OAUTH_ORIGIN", "https://zcode.z.ai")

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// ExpirySkew drops a token this long before a (rare) exp claim.
const ExpirySkew = 120 * time.Second

// AuthError is a typed failure with an HTTP status and a kind.
type AuthError struct {
	Msg    string
	Status int
	Body   any
	Kind   string // auth | config | cancelled | expired | rejected | protocol | refresh
}

func (e *AuthError) Error() string { return e.Msg }

// DecodeJWT parses a JWT's payload claims without verifying the signature.
func DecodeJWT(token string) (map[string]any, bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, false
	}
	return claims, true
}

// IsExpired reports whether the token carries an exp that has passed
// (plus skew). Tokens without exp — the plan JWT shape — are never "expired".
func IsExpired(token string, now time.Time) bool {
	claims, ok := DecodeJWT(token)
	if !ok {
		return false
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return false
	}
	return time.Unix(int64(exp), 0).Before(now.Add(ExpirySkew))
}

// DeviceFlow is one started OAuth device flow.
type DeviceFlow struct {
	FlowID       string    `json:"flow_id"`
	AuthorizeURL string    `json:"authorize_url"`
	ExpiresAt    time.Time `json:"expires_at"`
	IntervalSec  int       `json:"poll_interval_sec"`
	PollToken    string    `json:"-"`
}

// StartDeviceFlow begins the CLI OAuth device flow. The caller shows
// AuthorizeURL to the user; Poll resolves once they approve.
func StartDeviceFlow(ctx context.Context) (*DeviceFlow, error) {
	pollToken := make([]byte, 32)
	if _, err := randRead(pollToken); err != nil {
		return nil, &AuthError{Msg: "poll token entropy: " + err.Error(), Kind: "config"}
	}
	payload := strings.NewReader(`{"provider":"zai"}`)
	req, err := newRequest(ctx, "POST", OAuthBase+"/api/v1/oauth/cli/init", payload,
		map[string]string{
			"Authorization": "Bearer " + hexEncode(pollToken),
			"Content-Type":  "application/json",
			"Accept":        "application/json",
		})
	if err != nil {
		return nil, &AuthError{Msg: "build request: " + err.Error(), Kind: "config"}
	}
	body, status, err := doRequest(req)
	if err != nil {
		return nil, &AuthError{Msg: "device flow init: " + err.Error(), Kind: "auth"}
	}
	var out struct {
		Data struct {
			FlowID       string `json:"flow_id"`
			AuthorizeURL string `json:"authorize_url"`
			ExpiresAt    any    `json:"expires_at"`
			PollInterval int    `json:"poll_interval_sec"`
			PollToken    string `json:"poll_token"`
		} `json:"data"`
		Code any    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &AuthError{Msg: "device flow init: non-JSON reply", Status: status, Body: string(body), Kind: "protocol"}
	}
	if status < 200 || status >= 300 || out.Data.FlowID == "" || out.Data.AuthorizeURL == "" {
		return nil, &AuthError{Msg: fmt.Sprintf("device flow init failed (HTTP %d) %s", status, out.Msg), Status: status, Body: string(body), Kind: "auth"}
	}
	exp := time.Now().Add(5 * time.Minute)
	switch v := out.Data.ExpiresAt.(type) {
	case float64:
		if v > 1e12 {
			exp = time.UnixMilli(int64(v))
		} else {
			exp = time.Unix(int64(v), 0)
		}
	}
	interval := out.Data.PollInterval
	if interval <= 0 {
		interval = 2
	}
	return &DeviceFlow{
		FlowID:       out.Data.FlowID,
		AuthorizeURL: out.Data.AuthorizeURL,
		ExpiresAt:    exp,
		IntervalSec:  interval,
		PollToken:    firstNonEmpty(out.Data.PollToken, hexEncode(pollToken)),
	}, nil
}

// FlowResult is everything a caller needs to persist after approval.
type FlowResult struct {
	JWT          string
	User         map[string]any
	AccessToken  string
	RefreshToken string
}

// Poll polls the device flow until the user approves, it fails, or the flow
// expires.
func PollDeviceFlow(ctx context.Context, flow *DeviceFlow) (*FlowResult, error) {
	deadline := flow.ExpiresAt
	if deadline.IsZero() {
		deadline = time.Now().Add(5 * time.Minute)
	}
	interval := time.Duration(flow.IntervalSec) * time.Second
	if interval <= 0 {
		interval = 2 * time.Second
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, &AuthError{Msg: "device flow polling aborted", Kind: "cancelled"}
		}
		if time.Now().After(deadline) {
			return nil, &AuthError{Msg: "device flow expired before approval", Kind: "expired"}
		}
		req, err := newRequest(ctx, "GET",
			fmt.Sprintf("%s/api/v1/oauth/cli/poll/%s", OAuthBase, flow.FlowID), nil,
			map[string]string{"Authorization": "Bearer " + flow.PollToken})
		if err != nil {
			return nil, &AuthError{Msg: "build poll: " + err.Error(), Kind: "config"}
		}
		body, status, err := doRequest(req)
		if err != nil {
			return nil, &AuthError{Msg: "device flow poll: " + err.Error(), Status: status, Kind: "auth"}
		}
		var out struct {
			Data struct {
				Status string         `json:"status"`
				Token  string         `json:"token"`
				User   map[string]any `json:"user"`
				Zai    *oauthTokens   `json:"zai"`
				Big    *oauthTokens   `json:"bigmodel"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &out); err != nil || out.Data.Status == "" {
			return nil, &AuthError{Msg: "device flow poll: parse failed", Status: status, Body: string(body), Kind: "protocol"}
		}
		switch out.Data.Status {
		case "ready":
			if out.Data.Token == "" {
				return nil, &AuthError{Msg: "device flow returned no plan token", Kind: "protocol", Body: string(body)}
			}
			res := &FlowResult{JWT: out.Data.Token, User: out.Data.User}
			if out.Data.Zai != nil {
				res.AccessToken, res.RefreshToken = out.Data.Zai.AccessToken, out.Data.Zai.RefreshToken
			} else if out.Data.Big != nil {
				res.AccessToken, res.RefreshToken = out.Data.Big.AccessToken, out.Data.Big.RefreshToken
			}
			return res, nil
		case "failed":
			return nil, &AuthError{Msg: "device flow was rejected", Kind: "rejected", Body: string(body)}
		case "expired":
			return nil, &AuthError{Msg: "device flow expired before approval", Kind: "expired"}
		}
		select {
		case <-ctx.Done():
			return nil, &AuthError{Msg: "device flow polling aborted", Kind: "cancelled"}
		case <-time.After(interval):
		}
	}
}

type oauthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshPlanJWT best-effort refreshes a plan JWT from a device-flow refresh
// token. The desktop chain never refreshes proactively and the grant is not
// publicly documented; a rejection means re-run login (a 15-second phone
// approve).
func RefreshPlanJWT(ctx context.Context, refreshToken string) (*FlowResult, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, &AuthError{Msg: "no refresh token stored", Kind: "config"}
	}
	payload := strings.NewReader(fmt.Sprintf(`{"provider":"zai","grant_type":"refresh_token","refresh_token":%q}`, refreshToken))
	req, err := newRequest(ctx, "POST", OAuthBase+"/api/v1/oauth/token", payload,
		map[string]string{"Content-Type": "application/json", "Accept": "application/json"})
	if err != nil {
		return nil, &AuthError{Msg: "build refresh: " + err.Error(), Kind: "config"}
	}
	body, status, err := doRequest(req)
	if err != nil {
		return nil, &AuthError{Msg: "refresh request failed: " + err.Error(), Status: status, Kind: "refresh"}
	}
	var out struct {
		Data struct {
			Token string       `json:"token"`
			User  map[string]any `json:"user"`
			Zai   *oauthTokens `json:"zai"`
			Big   *oauthTokens `json:"bigmodel"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil || status < 200 || status >= 300 || out.Data.Token == "" {
		return nil, &AuthError{Msg: "plan token refresh rejected (re-login required)", Status: status, Body: string(body), Kind: "refresh"}
	}
	res := &FlowResult{JWT: out.Data.Token, User: out.Data.User, RefreshToken: refreshToken}
	if out.Data.Zai != nil {
		res.AccessToken, res.RefreshToken = out.Data.Zai.AccessToken, firstNonEmpty(out.Data.Zai.RefreshToken, refreshToken)
	} else if out.Data.Big != nil {
		res.AccessToken, res.RefreshToken = out.Data.Big.AccessToken, firstNonEmpty(out.Data.Big.RefreshToken, refreshToken)
	}
	return res, nil
}

// ResolvePlanJWT resolves a usable plan JWT without touching the network:
// explicit override (env) -> plan-jwt.json -> accounts store (caller merges)
// -> desktop store. Stale tokens are dropped: the gateway answers a billing
// error instead of a clear auth error for a dead token.
func ResolvePlanJWT(explicit string) string {
	if v := strings.TrimSpace(explicit); v != "" && !IsExpired(v, time.Now()) {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("ZCODE_PLAN_JWT")); v != "" && !IsExpired(v, time.Now()) {
		return v
	}
	if v := ReadBridgeTokenFile(); v != "" && !IsExpired(v, time.Now()) {
		return v
	}
	if v := DesktopStoreJWT(); v != "" && !IsExpired(v, time.Now()) {
		return v
	}
	return ""
}

// ReadBridgeTokenFile reads the single-token fallback file
// (ZCODE_PLAN_JWT_FILE or ./plan-jwt.json), ignoring a malformed file.
func ReadBridgeTokenFile() string {
	file := os.Getenv("ZCODE_PLAN_JWT_FILE")
	if file == "" {
		file = "plan-jwt.json"
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	var record struct {
		JWT string `json:"jwt"`
	}
	if json.Unmarshal(raw, &record) != nil || strings.TrimSpace(record.JWT) == "" {
		return ""
	}
	return strings.TrimSpace(record.JWT)
}

// --- desktop credential store (optional convenience) ---

const encPrefix = "enc:v1:"

// DesktopKeys names the store entries the bridge reads.
var DesktopKeys = struct {
	ZcodeJWT string
}{ZcodeJWT: "zcodejwttoken"}

func desktopCredentialsFile() string {
	dir := os.Getenv("ZCODE_STATE_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".zcode", "v2")
	}
	return filepath.Join(dir, "credentials.json")
}

// desktopStoreKey is SHA-256("zcode-credential-fallback:<platform>:<homedir>:<username>")
// — the desktop client's own fallback KDF.
func desktopStoreKey() []byte {
	username := ""
	if u, err := user.Current(); err == nil {
		username = u.Username
	}
	home, _ := os.UserHomeDir()
	sum := sha256.Sum256([]byte(fmt.Sprintf("zcode-credential-fallback:%s:%s:%s", runtimeOS(), home, username)))
	return sum[:]
}

// DesktopStoreJWT reads the plan JWT from the desktop client's encrypted
// credential store, when one exists on this machine. Absent file or
// undecryptable value = "" (the store is optional).
func DesktopStoreJWT() string {
	file := desktopCredentialsFile()
	if file == "" {
		return ""
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	var record map[string]any
	if json.Unmarshal(raw, &record) != nil {
		return ""
	}
	value, ok := record[DesktopKeys.ZcodeJWT].(string)
	if !ok {
		return ""
	}
	if !strings.HasPrefix(value, encPrefix) {
		return value // stored plaintext
	}
	plain, err := decryptValue(value)
	if err != nil {
		return "" // encrypted under a different machine identity
	}
	return plain
}

func decryptValue(value string) (string, error) {
	parts := strings.SplitN(strings.TrimPrefix(value, encPrefix), ".", 3)
	if len(parts) != 3 {
		return "", errors.New("malformed encrypted credential")
	}
	iv, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(desktopStoreKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, iv, append(data, tag...), nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
