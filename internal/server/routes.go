package server

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/azrinaldi/zcode-bridge/internal/accounts"
	"github.com/azrinaldi/zcode-bridge/internal/auth"
	"github.com/azrinaldi/zcode-bridge/internal/identity"
	"github.com/azrinaldi/zcode-bridge/internal/quota"
	"github.com/azrinaldi/zcode-bridge/internal/transport"
)

// Route dispatches one request; handler errors that happen after the
// headers are sent are impossible here because every handler writes its
// own status first.
func Route() http.Handler {
	return http.HandlerFunc(route)
}

func route(w http.ResponseWriter, r *http.Request) {
	if !cors(w, r) {
		return // preflight handled
	}
	pathName := strings.TrimRight(r.URL.Path, "/")
	if pathName == "" {
		pathName = "/"
	}
	accountID := r.URL.Query().Get("account")
	if accountID == "" {
		accountID = r.Header.Get("X-Zcode-Account")
	}

	switch {
	case r.Method == http.MethodGet && (pathName == "/health" || pathName == "/healthz"):
		handleHealth(w)
	case r.Method == http.MethodGet && (pathName == "/v1/models" || pathName == "/models"):
		sendJSON(w, 200, map[string]any{"object": "list", "data": liveModels(r.Context())})
	case r.Method == http.MethodGet && (pathName == "/v1/quota" || pathName == "/quota"):
		handleQuota(w, r, accountID)
	case r.Method == http.MethodPost && pathName == "/v1/messages":
		requireAuth(w, r, "anthropic", func() {
			handlePost(w, r, accountID, handleMessages)
		})
	case r.Method == http.MethodPost && pathName == "/v1/chat/completions":
		requireAuth(w, r, "openai", func() {
			handlePost(w, r, accountID, handleChatCompletions)
		})
	default:
		anthropicError(w, 404, fmt.Sprintf("No route for %s %s", r.Method, r.URL.Path), "not_found_error")
	}
}

// requireAuth gates inference routes; read-only observability routes stay
// open so localhost dashboards work without the token.
func requireAuth(w http.ResponseWriter, r *http.Request, dialect string, next func()) {
	if !authorized(r) {
		if dialect == "openai" {
			openAIError(w, 401, "Invalid bridge token", "invalid_api_key")
		} else {
			anthropicError(w, 401, "Invalid bridge token", "authentication_error")
		}
		return
	}
	next()
}

func handlePost(w http.ResponseWriter, r *http.Request, accountID string, handler func(http.ResponseWriter, *http.Request, map[string]any, string)) {
	raw, err := readBody(r)
	if err != nil {
		anthropicError(w, 400, "Failed to read request body", "invalid_request_error")
		return
	}
	if len(raw) > maxBodyBytes {
		anthropicError(w, 413, "Request body too large", "invalid_request_error")
		return
	}
	body, ok := parseJSON(raw)
	if !ok {
		anthropicError(w, 400, "Invalid JSON body", "invalid_request_error")
		return
	}
	handler(w, r, body, accountID)
}

// handleHealth reports lane, credential and rotation state (no secrets).
func handleHealth(w http.ResponseWriter) {
	ring := accounts.Summarize()
	deviceMid := identity.ResolveDeviceMid()
	planJwt := map[string]any{"present": false}
	if len(ring) > 0 {
		planJwt = map[string]any{"present": true, "count": len(ring)}
	} else if jwt := auth.ResolvePlanJWT(""); jwt != "" {
		claims, _ := auth.DecodeJWT(jwt)
		entry := map[string]any{"present": true}
		if iat, ok := claims["iat"].(float64); ok {
			entry["issuedAt"] = time.Unix(int64(iat), 0).UTC().Format(time.RFC3339)
		}
		if uid, ok := claims["user_id"].(string); ok {
			entry["userId"] = uid
		}
		planJwt = entry
	}
	authMode := "open (localhost)"
	if cfg.BridgeToken != "" {
		authMode = "bridge token required"
	}
	sendJSON(w, 200, map[string]any{
		"ok":            true,
		"lane":          "zcode-plan/anthropic",
		"upstream":      transport.InferenceOrigin + transport.PlanAnthropicPath,
		"clientVersion": identity.ResolveAppVersion(),
		"deviceMid": func() string {
			if deviceMid != "" {
				return "set"
			}
			return "MISSING (control calls may fail 3001)"
		}(),
		"accounts": ring,
		"planJwt":  planJwt,
		"auth":     authMode,
		"version":  identity.ResolveAppVersion(),
	})
}

// handleQuota serves the billing readout for the first usable account (or
// the ?account= pin).
func handleQuota(w http.ResponseWriter, r *http.Request, accountID string) {
	cands, err := transport.Candidates(accountID, "")
	if err != nil || len(cands) == 0 {
		sendJSON(w, 502, map[string]any{"ok": false, "error": "no usable plan credential: run login"})
		return
	}
	acct := cands[0]
	q, err := quota.ReadQuota(r.Context(), acct.JWT, acct.DeviceID)
	if err != nil {
		sendJSON(w, 502, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	q.Account = firstNonEmpty(acct.Label, acct.ID, accountID, "default")
	sendJSON(w, 200, q)
}

// cors implements opt-in browser support: ZCODE_CORS_ORIGIN="*" or a comma
// list of allowed origins. Returns false when the request was handled as a
// preflight.
func cors(w http.ResponseWriter, r *http.Request) bool {
	corsOrigins := strings.TrimSpace(firstNonEmpty(os.Getenv("ZCODE_CORS_ORIGIN"), ""))
	if corsOrigins == "" {
		return true
	}
	origin := r.Header.Get("Origin")
	allowed := corsOrigins == "*"
	if !allowed && origin != "" {
		for _, o := range strings.Split(corsOrigins, ",") {
			if strings.TrimSpace(o) == origin {
				allowed = true
				break
			}
		}
	}
	if allowed && origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Api-Key, X-Session-Id, X-Zcode-Account")
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	return true
}

// ListenAndServe starts the HTTP server. keepAlive timeouts mirror the JS
// server's 65s values so long SSE streams survive intermediary idle cuts.
func ListenAndServe() error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	srv := &http.Server{
		Addr:              addr,
		Handler:           Route(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       66 * time.Second,
	}
	return srv.ListenAndServe()
}

