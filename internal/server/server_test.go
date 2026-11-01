package server

// End-to-end test suite against a stub gateway, mirroring the JS smoke
// checks 1:1. The stub answers the plan lane, the billing pair and the
// token endpoint so no real credential is touched. All JWTs here are
// synthetic fixtures (unsigned base64 payloads), never secrets.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azrinaldi/zcode-bridge/internal/accounts"
	"github.com/azrinaldi/zcode-bridge/internal/auth"
	"github.com/azrinaldi/zcode-bridge/internal/systemprompt"
	"github.com/azrinaldi/zcode-bridge/internal/transport"
)

func fakeJWT(user string) string {
	payload := base64URL([]byte(fmt.Sprintf(`{"user_id":%q,"iat":%d}`, user, time.Now().Unix())))
	return "eyJhbGciOiJIUzI1NiJ9." + payload + ".sig"
}

func base64URL(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := make([]byte, 0, (len(b)+2)/3*4)
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		copy(chunk[:], b[i:])
		n := 0x10000*int(chunk[0]) + 0x100*int(chunk[1]) + int(chunk[2])
		out = append(out, alphabet[(n>>18)&63], alphabet[(n>>12)&63])
		if i+1 < len(b) {
			out = append(out, alphabet[(n>>6)&63])
		} else {
			out = append(out, '=')
		}
		if i+2 < len(b) {
			out = append(out, alphabet[n&63])
		} else {
			out = append(out, '=')
		}
	}
	return strings.TrimRight(string(out), "=")
}

var (
	JWT     = fakeJWT("u_smoke")
	FAILJWT = fakeJWT("u_spent")
	EXPIRED = "EXPIRED"
)

type seenState struct {
	mu           sync.Mutex
	anthropic    map[string]any
	anthropicHdr http.Header
	bearers      []string
	refreshCalls int
	currentHdr   http.Header
	balanceHdr   http.Header
}

var seen = &seenState{}

func stubGateway() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		seen.mu.Lock()
		seen.refreshCalls++
		seen.mu.Unlock()
		writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{
			"token": JWT, "zai": map[string]any{"access_token": "at-new", "refresh_token": "rt-new"},
		}})
	})
	mux.HandleFunc("/api/v1/zcode-plan/anthropic/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen.mu.Lock()
		seen.anthropic = body
		seen.anthropicHdr = r.Header.Clone()
		seen.bearers = append(seen.bearers, r.Header.Get("Authorization"))
		seen.mu.Unlock()
		bearer := r.Header.Get("Authorization")
		if r.Header.Get("X-Client-Sig") != "" || r.Header.Get("X-Client-Pow") != "" || r.Header.Get("X-App-Id") != "" {
			writeJSON(w, 429, map[string]any{"code": 1113, "msg": "insufficient balance (signed request hit the paid lane)"})
			return
		}
		if !strings.HasPrefix(bearer, "Bearer ") {
			writeJSON(w, 401, map[string]any{"code": 401, "msg": "unauthorized"})
			return
		}
		if bearer == "Bearer "+FAILJWT {
			writeJSON(w, 429, map[string]any{"code": 1113, "msg": "plan allowance spent for this account"})
			return
		}
		if bearer == "Bearer "+EXPIRED {
			writeJSON(w, 401, map[string]any{"code": 401, "msg": "token expired"})
			return
		}
		sys, _ := body["system"].([]any)
		ok := len(sys) == 3
		if ok {
			b1, _ := sys[0].(map[string]any)
			b2, _ := sys[1].(map[string]any)
			if b1["text"] != systemprompt.Captured().CliPrefix ||
				!strings.HasPrefix(str(b2["text"]), systemprompt.Captured().StablePrefix[:60]) {
				ok = false
			}
		}
		if !ok {
			writeJSON(w, 405, map[string]any{"code": 3012, "msg": "request has been blocked due to unusual activity."})
			return
		}
		tools, _ := body["tools"].([]any)
		stream := body["stream"] == true
		if !stream {
			if len(tools) > 0 {
				writeJSON(w, 200, map[string]any{
					"id": "msg_stub", "type": "message", "role": "assistant", "model": "glm-5.3-flash",
					"content":     []any{map[string]any{"type": "tool_use", "id": "toolu_stub", "name": "get_weather", "input": map[string]any{"city": "Jakarta"}}},
					"stop_reason": "tool_use", "usage": map[string]any{"input_tokens": 11, "output_tokens": 7},
				})
				return
			}
			writeJSON(w, 200, map[string]any{
				"id": "msg_stub", "type": "message", "role": "assistant", "model": "glm-5.3-flash",
				"content":     []any{map[string]any{"type": "text", "text": "STUB-OK"}},
				"stop_reason": "end_turn", "usage": map[string]any{"input_tokens": 11, "output_tokens": 7},
			})
			return
		}
		var events []map[string]any
		if len(tools) > 0 {
			events = []map[string]any{
				{"type": "message_start", "message": map[string]any{"id": "msg_stub", "model": "glm-5.3-flash", "usage": map[string]any{"input_tokens": 0, "output_tokens": 0}}},
				{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "tool_use", "id": "toolu_stub", "name": "get_weather"}},
				{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "input_json_delta", "partial_json": `{"city":"Jakarta"}`}},
				{"type": "content_block_stop", "index": 0},
				{"type": "message_delta", "delta": map[string]any{"stop_reason": "tool_use"}, "usage": map[string]any{"input_tokens": 12, "output_tokens": 9}},
				{"type": "message_stop"},
			}
		} else {
			events = []map[string]any{
				{"type": "message_start", "message": map[string]any{"id": "msg_stub", "model": "glm-5.3-flash", "usage": map[string]any{"input_tokens": 0, "output_tokens": 0}}},
				{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}},
				{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": "STUB"}},
				{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": "-OK"}},
				{"type": "content_block_stop", "index": 0},
				{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn"}, "usage": map[string]any{"input_tokens": 10, "output_tokens": 5}},
				{"type": "message_stop"},
			}
		}
		w.Header().Set("content-type", "text/event-stream")
		w.WriteHeader(200)
		for _, e := range events {
			encoded, _ := json.Marshal(e)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e["type"], encoded)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	})
	mux.HandleFunc("/api/v1/zcode-plan/billing/current", func(w http.ResponseWriter, r *http.Request) {
		seen.mu.Lock()
		seen.currentHdr = r.Header.Clone()
		seen.mu.Unlock()
		// Real behaviour 2026-10-30: with the control headers the payload is empty.
		plans := []any{}
		if r.Header.Get("X-Device-Mid") == "" {
			plans = []any{map[string]any{
				"name": "ZCODE WEEKEND BUILD (current-fallback)", "plan_id": "wk", "status": "active",
				"ends_at": 1793581200, "priority": 101,
				"entitlements": []any{map[string]any{
					"entitlement_id": "ent_wk", "show_name": "GLM-5.3-Flash", "meter": "model_usage",
					"unit_type": "token", "capabilities": []string{"model:glm-5.3-flash"},
					"grant_units": 500000000, "period": "one_time", "priority": 101,
				}},
			}}
		}
		writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"server_time": time.Now().Unix(), "plans": plans}})
	})
	mux.HandleFunc("/api/v1/zcode-plan/billing/balance", func(w http.ResponseWriter, r *http.Request) {
		seen.mu.Lock()
		seen.balanceHdr = r.Header.Clone()
		seen.mu.Unlock()
		if r.Header.Get("X-Device-Mid") == "" {
			writeJSON(w, 400, map[string]any{"code": 3001, "msg": "parameter error"})
			return
		}
		writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{
			"server_time": time.Now().Unix(),
			"plans": []any{
				map[string]any{"name": "ZCODE WEEKEND BUILD", "plan_id": "wk", "status": "active", "ends_at": 1793581200, "priority": 101,
					"entitlements": []any{map[string]any{"entitlement_id": "ent_wk", "show_name": "GLM-5.3-Flash", "meter": "model_usage", "unit_type": "token", "capabilities": []string{"model:glm-5.3-flash"}, "grant_units": 500000000, "period": "one_time", "priority": 101}}},
				map[string]any{"name": "ZCode Start Plan", "plan_id": "sp", "status": "active", "ends_at": 1730000000, "priority": 90,
					"entitlements": []any{
						map[string]any{"entitlement_id": "ent_53", "show_name": "GLM-5.3", "meter": "model_usage", "unit_type": "token", "capabilities": []string{"model:glm-5.3"}, "grant_units": 3000000, "period": "daily", "priority": 110},
						map[string]any{"entitlement_id": "ent_flash", "show_name": "GLM-5.3-Flash", "meter": "model_usage", "unit_type": "token", "capabilities": []string{"model:glm-5.3-flash"}, "grant_units": 5000000, "period": "daily", "priority": 80},
					}},
			},
			"balances": []any{
				map[string]any{"entitlement_id": "ent_53", "show_name": "GLM-5.3", "plan_id": "sp", "period": "daily", "period_start": 1793376000, "period_end": 1793462399, "total_units": 3000000, "used_units": 22, "remaining_units": 2999978, "available_units": 2999978},
				map[string]any{"entitlement_id": "ent_wk", "show_name": "GLM-5.3-Flash", "plan_id": "wk", "period": "one_time", "total_units": 500000000, "used_units": 0, "remaining_units": 500000000, "available_units": 500000000},
				map[string]any{"entitlement_id": "ent_flash", "show_name": "GLM-5.3-Flash", "plan_id": "sp", "period": "daily", "period_start": 1793376000, "period_end": 1793462399, "total_units": 5000000, "used_units": 27927, "remaining_units": 4972073, "available_units": 4972073},
			},
		}})
	})
	srv := httptest.NewServer(mux)
	return srv
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

var (
	bridge     *httptest.Server
	bridgeOnce sync.Once
)

func bridgeURL() string { return bridge.URL }

func setupBridge(t *testing.T) {
	t.Helper()
	bridgeOnce.Do(func() {
		gateway := stubGateway()
		// No per-test Cleanup: bridgeOnce keeps these alive for the whole
		// test binary; the process exit reclaims them.
		os.Setenv("ZCODE_INFERENCE_ORIGIN", gateway.URL)
		transport.InferenceOrigin = gateway.URL
		os.Setenv("ZCODE_OAUTH_ORIGIN", gateway.URL)
		auth.OAuthBase = gateway.URL
		os.Setenv("ZCODE_PLAN_JWT", JWT)
		os.Setenv("ZCODE_PLAN_JWT_FILE", filepath.Join(os.TempDir(), "zcode-smoke-no-such-jwt.json"))
		os.Setenv("ZCODE_IDENTITY_DEVICE_MID", "0a7c2d9d-ce62-4456-aa65-625511ff1ef0")
		os.Setenv("ZCODE_RETRY_BASE_MS", "10")
		accountsFile := filepath.Join(os.TempDir(), fmt.Sprintf("zcode-smoke-accounts-%d.json", os.Getpid()))
		os.Setenv("ZCODE_ACCOUNTS_FILE", accountsFile)
		accounts.ResetForTest()
		Configure(Config{Port: 0, Host: "127.0.0.1", BridgeToken: "", ModelsCache: 100 * time.Millisecond})
		bridge = httptest.NewServer(Route())
	})
}

func doRequest(t *testing.T, method, path string, body map[string]any) (int, string, map[string]any) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, bridgeURL()+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(res.Body)
	text := buf.String()
	var parsed map[string]any
	if strings.HasPrefix(strings.TrimSpace(text), "{") || strings.HasPrefix(strings.TrimSpace(text), "[") {
		_ = json.Unmarshal([]byte(text), &parsed)
	}
	return res.StatusCode, text, parsed
}

func resetSeen() {
	seen.mu.Lock()
	defer seen.mu.Unlock()
	seen.anthropic = nil
	seen.bearers = nil
	seen.refreshCalls = 0
	seen.currentHdr = nil
	seen.balanceHdr = nil
}

func TestHealthReportsPlanLane(t *testing.T) {
	setupBridge(t)
	resetSeen()
	status, _, body := doRequest(t, "GET", "/health", nil)
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	if body["lane"] != "zcode-plan/anthropic" {
		t.Fatalf("lane = %v", body["lane"])
	}
	planJwt := body["planJwt"].(map[string]any)
	if planJwt["present"] != true {
		t.Fatalf("planJwt = %v", planJwt)
	}
}

func TestAnthropicPassthroughIdentityBlocks(t *testing.T) {
	setupBridge(t)
	resetSeen()
	status, text, body := doRequest(t, "POST", "/v1/messages", map[string]any{
		"model":    "GLM-5.3-Flash",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
		"system":   "You are a terse assistant.",
	})
	if status != 200 {
		t.Fatalf("status %d: %s", status, text)
	}
	content := body["content"].([]any)
	if str(content[0].(map[string]any)["text"]) != "STUB-OK" {
		t.Fatalf("content = %v", content)
	}
	seen.mu.Lock()
	sys := seen.anthropic["system"].([]any)
	hdr := seen.anthropicHdr
	seen.mu.Unlock()
	if len(sys) != 3 {
		t.Fatalf("system blocks = %d", len(sys))
	}
	b1 := sys[0].(map[string]any)
	b2 := sys[1].(map[string]any)
	b3 := sys[2].(map[string]any)
	if str(b1["text"]) != systemprompt.Captured().CliPrefix {
		t.Fatal("block 1 must be cliPrefix verbatim")
	}
	if !strings.HasPrefix(str(b2["text"]), systemprompt.Captured().StablePrefix[:80]) {
		t.Fatal("block 2 must start with stablePrefix")
	}
	if !strings.Contains(str(b3["text"]), "terse assistant") {
		t.Fatal("client system rides block 3")
	}
	if hdr.Get("X-Client-Sig") != "" {
		t.Fatal("no signed headers on the plan lane")
	}
	if hdr.Get("Authorization") != "Bearer "+JWT {
		t.Fatalf("bearer = %q", hdr.Get("Authorization"))
	}
	if !regexp.MustCompile(`^session_[0-9a-f]{32}$`).MatchString(hdr.Get("X-Session-Id")) {
		t.Fatalf("x-session-id = %q", hdr.Get("X-Session-Id"))
	}
}

func TestOpenAIStreamChunks(t *testing.T) {
	setupBridge(t)
	resetSeen()
	req, _ := http.NewRequest("POST", bridgeURL()+"/v1/chat/completions", bytes.NewReader([]byte(
		`{"model":"glm-5.3-flash","stream":true,"messages":[{"role":"system","content":"be terse"},{"role":"user","content":"hi"}]}`)))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("stream http %d", res.StatusCode)
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(res.Body)
	text := buf.String()
	if !strings.Contains(text, "chat.completion.chunk") {
		t.Fatalf("missing chunks: %.200s", text)
	}
	if !strings.Contains(text, "STUB") {
		t.Fatal("text deltas forwarded")
	}
	if !strings.Contains(text, "[DONE]") {
		t.Fatal("stream terminated with [DONE]")
	}
}

func TestSessionAffinity(t *testing.T) {
	setupBridge(t)
	resetSeen()
	doRequest(t, "POST", "/v1/chat/completions", map[string]any{"model": "glm-5.3-flash", "user": "conv-42", "messages": []any{map[string]any{"role": "user", "content": "a"}}})
	seen.mu.Lock()
	first := seen.anthropicHdr.Get("X-Session-Id")
	seen.mu.Unlock()
	doRequest(t, "POST", "/v1/chat/completions", map[string]any{"model": "glm-5.3-flash", "user": "conv-42", "messages": []any{map[string]any{"role": "user", "content": "b"}}})
	seen.mu.Lock()
	second := seen.anthropicHdr.Get("X-Session-Id")
	seen.mu.Unlock()
	if first != second {
		t.Fatalf("session id must be stable per conversation: %q vs %q", first, second)
	}
	doRequest(t, "POST", "/v1/chat/completions", map[string]any{"model": "glm-5.3-flash", "user": "conv-43", "messages": []any{map[string]any{"role": "user", "content": "b"}}})
	seen.mu.Lock()
	third := seen.anthropicHdr.Get("X-Session-Id")
	seen.mu.Unlock()
	if third == first {
		t.Fatal("a different conversation gets a different session")
	}
}

func TestToolRoundTrip(t *testing.T) {
	setupBridge(t)
	resetSeen()
	status, text, body := doRequest(t, "POST", "/v1/chat/completions", map[string]any{
		"model":    "glm-5.3-flash",
		"messages": []any{map[string]any{"role": "user", "content": "weather?"}},
		"tools": []any{map[string]any{"type": "function", "function": map[string]any{
			"name": "get_weather", "description": "d",
			"parameters": map[string]any{"type": "object", "properties": map[string]any{"city": map[string]any{"type": "string"}}},
		}}},
	})
	if status != 200 {
		t.Fatalf("status %d: %s", status, text)
	}
	choices := body["choices"].([]any)
	msg := choices[0].(map[string]any)["message"].(map[string]any)
	toolCalls, hasCalls := msg["tool_calls"].([]any)
	if !hasCalls || len(toolCalls) == 0 {
		raw, _ := json.Marshal(body)
		t.Fatalf("no tool_calls: %.300s", raw)
	}
	call := toolCalls[0].(map[string]any)["function"].(map[string]any)
	if str(call["name"]) != "get_weather" {
		t.Fatalf("tool name = %v", call["name"])
	}
	var args map[string]any
	if json.Unmarshal([]byte(str(call["arguments"])), &args) != nil || args["city"] != "Jakarta" {
		t.Fatalf("arguments = %v", call["arguments"])
	}
	if str(choices[0].(map[string]any)["finish_reason"]) != "tool_calls" {
		t.Fatalf("finish_reason = %v", choices[0].(map[string]any)["finish_reason"])
	}
	seen.mu.Lock()
	tools := seen.anthropic["tools"].([]any)
	seen.mu.Unlock()
	if str(tools[0].(map[string]any)["input_schema"].(map[string]any)["type"]) != "object" {
		t.Fatal("tools translated to input_schema")
	}
	// Follow-up: role:"tool" must become a tool_result block inside a user turn.
	status, text, _ = doRequest(t, "POST", "/v1/chat/completions", map[string]any{
		"model": "glm-5.3-flash",
		"messages": []any{
			map[string]any{"role": "user", "content": "weather?"},
			map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{map[string]any{"id": "toolu_stub", "type": "function", "function": map[string]any{"name": "get_weather", "arguments": `{"city":"Jakarta"}`}}}},
			map[string]any{"role": "tool", "tool_call_id": "toolu_stub", "content": "31C"},
			map[string]any{"role": "user", "content": "thanks"},
		},
	})
	if status != 200 {
		t.Fatalf("follow-up status %d: %s", status, text)
	}
	seen.mu.Lock()
	msgs := seen.anthropic["messages"].([]any)
	seen.mu.Unlock()
	found := false
	for _, m := range msgs {
		mm, ok := m.(map[string]any)
		if !ok || mm["role"] != "user" {
			continue
		}
		content, ok := mm["content"].([]any)
		if !ok {
			continue
		}
		for _, b := range content {
			if bm, ok := b.(map[string]any); ok && bm["type"] == "tool_result" {
				found = true
			}
		}
	}
	if !found {
		raw, _ := json.Marshal(msgs)
		t.Fatalf("no tool_result block: %.400s", raw)
	}
}

func TestModelsMergesEntitlements(t *testing.T) {
	setupBridge(t)
	resetSeen()
	status, _, body := doRequest(t, "GET", "/v1/models", nil)
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	data := body["data"].([]any)
	var flash, glm map[string]any
	for _, m := range data {
		mm := m.(map[string]any)
		switch mm["id"] {
		case "glm-5.3-flash":
			flash = mm
		case "glm-5.3":
			glm = mm
		}
	}
	if flash == nil || glm == nil {
		t.Fatalf("missing models: %v", body["data"])
	}
	if flash["plan_remaining_tokens"].(float64) != 500000000+4972073 {
		t.Fatalf("flash remaining = %v", flash["plan_remaining_tokens"])
	}
	if glm["plan_remaining_tokens"].(float64) != 2999978 {
		t.Fatalf("glm remaining = %v", glm["plan_remaining_tokens"])
	}
	seen.mu.Lock()
	balanceHdr := seen.balanceHdr
	currentSeen := seen.currentHdr != nil
	seen.mu.Unlock()
	if balanceHdr.Get("X-Device-Mid") == "" {
		t.Fatal("balance calls must carry X-Device-Mid")
	}
	if currentSeen {
		t.Fatal("healthy balance response must not trigger the current fallback")
	}
}

func TestQuotaPerPlanRows(t *testing.T) {
	setupBridge(t)
	resetSeen()
	status, text, body := doRequest(t, "GET", "/v1/quota", nil)
	if status != 200 {
		t.Fatalf("status %d: %s", status, text)
	}
	if body["source"] != "balance" {
		t.Fatalf("source = %v", body["source"])
	}
	rows := body["rows"].([]any)
	if len(rows) != 3 {
		t.Fatalf("rows = %d", len(rows))
	}
	for _, r := range rows {
		row := r.(map[string]any)
		if row["plan_id"] == "wk" {
			if row["plan_name"] != "ZCODE WEEKEND BUILD" {
				t.Fatalf("wk plan_name = %v", row["plan_name"])
			}
			if row["total_units"].(float64) != 500000000 {
				t.Fatalf("wk total = %v", row["total_units"])
			}
		}
		if row["entitlement_id"] == "ent_53" {
			if row["period_start"].(float64) != 1793376000 || row["period_end"].(float64) != 1793462399 {
				t.Fatalf("daily window = %v..%v", row["period_start"], row["period_end"])
			}
		}
	}
	if errs, ok := body["errors"].([]any); ok && len(errs) != 0 {
		t.Fatalf("errors = %v", errs)
	}
}

func TestSignedHeadersNeverSent(t *testing.T) {
	setupBridge(t)
	resetSeen()
	status, text, _ := doRequest(t, "POST", "/v1/chat/completions", map[string]any{
		"model": "glm-5.3-flash", "messages": []any{map[string]any{"role": "user", "content": "x"}},
	})
	if status != 200 {
		t.Fatalf("default path must never sign: %d %s", status, text)
	}
}

func writeAccounts(t *testing.T, entries []map[string]any, def string) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"version": 1, "default": def, "accounts": entries})
	accountsFile := os.Getenv("ZCODE_ACCOUNTS_FILE")
	if err := os.WriteFile(accountsFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	accounts.ResetForTest()
}

func day() int64 { return 86400000 }

func TestMultiAccountRotation(t *testing.T) {
	setupBridge(t)
	writeAccounts(t, []map[string]any{
		{"id": "spent", "label": "spent", "jwt": FAILJWT, "userId": "u_spent", "deviceId": "0a7c2d9d-ce62-4456-aa65-625511ff1ef0", "sessionSeed": "seed-spent", "expiresAt": time.Now().UnixMilli() + day(), "needsReauth": false},
		{"id": "good", "label": "good", "jwt": JWT, "userId": "u_smoke", "deviceId": "0a7c2d9d-ce62-4456-aa65-625511ff1ef0", "sessionSeed": "seed-good", "expiresAt": time.Now().UnixMilli() + day(), "needsReauth": false},
	}, "spent")
	resetSeen()
	before := len(seenBearers())
	status, text, _ := doRequest(t, "POST", "/v1/chat/completions", map[string]any{"model": "glm-5.3-flash", "messages": []any{map[string]any{"role": "user", "content": "rotate me"}}})
	if status != 200 {
		t.Fatalf("status %d: %s", status, text)
	}
	used := seenBearers()[before:]
	if len(used) != 2 {
		t.Fatalf("bearers = %v", used)
	}
	if used[0] != "Bearer "+FAILJWT {
		t.Fatal("default account tried first")
	}
	if used[1] != "Bearer "+JWT {
		t.Fatal("rotated to the healthy account after 1113")
	}
	status, _, health := doRequest(t, "GET", "/health", nil)
	if status != 200 {
		t.Fatal("health failed")
	}
	ring := health["accounts"].([]any)
	if len(ring) != 2 {
		t.Fatalf("health accounts = %d", len(ring))
	}
	var spent map[string]any
	for _, a := range ring {
		if str(a.(map[string]any)["id"]) == "spent" {
			spent = a.(map[string]any)
		}
	}
	if spent == nil || str(spent["cooldownUntil"]) == "" {
		t.Fatal("spent account shows its cooldown")
	}
}

func seenBearers() []string {
	seen.mu.Lock()
	defer seen.mu.Unlock()
	return append([]string(nil), seen.bearers...)
}

func TestRefreshOn401(t *testing.T) {
	setupBridge(t)
	writeAccounts(t, []map[string]any{
		{"id": "exp", "label": "exp", "jwt": EXPIRED, "refreshToken": "rt-old", "userId": "u_smoke", "deviceId": "0a7c2d9d-ce62-4456-aa65-625511ff1ef0", "sessionSeed": "seed-exp", "expiresAt": time.Now().UnixMilli() + day(), "needsReauth": false},
		{"id": "spent", "label": "spent", "jwt": FAILJWT, "userId": "u_spent", "deviceId": "0a7c2d9d-ce62-4456-aa65-625511ff1ef0", "sessionSeed": "seed-spent", "expiresAt": time.Now().UnixMilli() + day(), "needsReauth": false},
		{"id": "good", "label": "good", "jwt": JWT, "userId": "u_smoke", "deviceId": "0a7c2d9d-ce62-4456-aa65-625511ff1ef0", "sessionSeed": "seed-good", "expiresAt": time.Now().UnixMilli() + day(), "needsReauth": false},
	}, "exp")
	resetSeen()
	before := len(seenBearers())
	status, text, _ := doRequest(t, "POST", "/v1/chat/completions", map[string]any{"model": "glm-5.3-flash", "messages": []any{map[string]any{"role": "user", "content": "refresh me"}}})
	if status != 200 {
		t.Fatalf("status %d: %s", status, text)
	}
	seen.mu.Lock()
	refreshCalls := seen.refreshCalls
	seen.mu.Unlock()
	if refreshCalls != 1 {
		t.Fatalf("token endpoint calls = %d", refreshCalls)
	}
	used := seenBearers()[before:]
	if len(used) != 2 {
		t.Fatalf("bearers = %v", used)
	}
	if used[0] != "Bearer "+EXPIRED {
		t.Fatal("expired token tried first")
	}
	if used[1] != "Bearer "+JWT {
		t.Fatal("retried with the refreshed token")
	}
	raw, err := os.ReadFile(os.Getenv("ZCODE_ACCOUNTS_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Accounts []map[string]any `json:"accounts"`
	}
	if json.Unmarshal(raw, &stored) != nil {
		t.Fatal("corrupt accounts file")
	}
	for _, a := range stored.Accounts {
		if a["id"] == "exp" {
			if a["jwt"] != JWT {
				t.Fatal("refreshed token persisted")
			}
			if a["refreshToken"] != "rt-new" {
				t.Fatal("rotated refresh token persisted")
			}
		}
	}
}

func TestAccountPinnedSkipsRotation(t *testing.T) {
	setupBridge(t)
	writeAccounts(t, []map[string]any{
		{"id": "spent", "label": "spent", "jwt": FAILJWT, "userId": "u_spent", "deviceId": "0a7c2d9d-ce62-4456-aa65-625511ff1ef0", "sessionSeed": "seed-spent", "expiresAt": time.Now().UnixMilli() + day(), "needsReauth": false},
		{"id": "good", "label": "good", "jwt": JWT, "userId": "u_smoke", "deviceId": "0a7c2d9d-ce62-4456-aa65-625511ff1ef0", "sessionSeed": "seed-good", "expiresAt": time.Now().UnixMilli() + day(), "needsReauth": false},
	}, "spent")
	resetSeen()
	status, _, _ := doRequest(t, "POST", "/v1/chat/completions?account=spent", map[string]any{"model": "glm-5.3-flash", "messages": []any{map[string]any{"role": "user", "content": "pinned"}}})
	if status != 429 {
		t.Fatalf("spent account answers its own error when pinned: %d", status)
	}
}
