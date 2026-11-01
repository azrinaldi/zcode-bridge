// Package accounts is the multi-account store for the plan lane.
//
// Each entry is one ZCode plan authorization obtained by `zcode-bridge login`
// (OAuth device flow — approve the printed URL in any browser signed in to
// Z.ai; the desktop app is not required). The bridge rotates inference calls
// across healthy accounts: when one trips its allowance (429/1113), a hard
// auth failure (401), or persistent account concurrency (3008), it cools
// down and the next account takes over.
//
// File shape (0600, path overridable via ZCODE_ACCOUNTS_FILE):
//
//	{ "version": 1, "default": "<id>",
//	  "accounts": [ { "id", "label", "jwt", "refreshToken", "accessToken",
//	                  "userId", "email", "deviceId", "sessionSeed",
//	                  "obtainedAt", "expiresAt", "needsReauth" } ] }
//
// The single-token fallbacks keep working: when this store is empty the
// bridge answers as one account from ZCODE_PLAN_JWT -> plan-jwt.json -> the
// desktop credential store, exactly as before.
package accounts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/azrinaldi/zcode-bridge/internal/auth"
)

// Account is one stored plan authorization.
type Account struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	JWT          string `json:"jwt"`
	RefreshToken string `json:"refreshToken,omitempty"`
	AccessToken  string `json:"accessToken,omitempty"`
	UserID       string `json:"userId,omitempty"`
	Email        string `json:"email,omitempty"`
	DeviceID     string `json:"deviceId,omitempty"`
	SessionSeed  string `json:"sessionSeed,omitempty"`
	ObtainedAt   string `json:"obtainedAt,omitempty"`
	ExpiresAt    int64  `json:"expiresAt,omitempty"` // unix ms; 0 = unknown
	NeedsReauth  bool   `json:"needsReauth,omitempty"`
}

type store struct {
	Version  int       `json:"version"`
	Default  string    `json:"default,omitempty"`
	Accounts []Account `json:"accounts"`
}

// Summary is the non-secret view for /health and login --list.
type Summary struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	Email         string `json:"email"`
	Default       bool   `json:"default"`
	HasRefresh    bool   `json:"hasRefresh"`
	ExpiresAt     int64  `json:"expiresAt"`
	Expired       bool   `json:"expired"`
	NeedsReauth   bool   `json:"needsReauth"`
	CooldownUntil string `json:"cooldownUntil"`
}

var (
	mu      sync.Mutex
	runtime = map[string]*state{} // id -> live cooldown state (not persisted)
)

type state struct {
	cooldownUntil time.Time
	failures      int
}

func cooldownDefault() time.Duration {
	if v := envMs("ZCODE_ACCOUNT_COOLDOWN_MS", 15*60*1000); v > 0 {
		return time.Duration(v) * time.Millisecond
	}
	return 15 * time.Minute
}

func AccountsFile() string {
	if f := os.Getenv("ZCODE_ACCOUNTS_FILE"); f != "" {
		return f
	}
	return filepath.Join("data", "accounts.json")
}

func readStore() store {
	var rec store
	raw, err := os.ReadFile(AccountsFile())
	if err != nil || json.Unmarshal(raw, &rec) != nil || rec.Accounts == nil {
		return store{Version: 1, Accounts: []Account{}}
	}
	return rec
}

func writeStore(rec store) error {
	if err := os.MkdirAll(filepath.Dir(AccountsFile()), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	// 0600: the file carries plan JWTs.
	if err := os.WriteFile(AccountsFile(), raw, 0o600); err != nil {
		return err
	}
	// A pre-existing file keeps its old mode; enforce 0600 on every write.
	if info, err := os.Stat(AccountsFile()); err == nil && info.Mode().Perm() != 0o600 {
		_ = os.Chmod(AccountsFile(), 0o600)
	}
	return nil
}

func idForJWT(jwt string) string {
	claims, ok := auth.DecodeJWT(jwt)
	if ok {
		if uid, _ := claims["user_id"].(string); uid != "" {
			if len(uid) > 8 {
				return uid[:8]
			}
			return uid
		}
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Upsert stores one authorization (add or refresh by id), keeping the
// account's existing deviceId/sessionSeed/email.
func Upsert(id, label, jwt, refreshToken, accessToken string, expiresAt int64) Account {
	mu.Lock()
	defer mu.Unlock()
	rec := readStore()
	claims, _ := auth.DecodeJWT(jwt)
	userID := ""
	if claims != nil {
		if v, _ := claims["user_id"].(string); v != "" {
			userID = v
		} else if v, _ := claims["sub"].(string); v != "" {
			userID = v
		}
	}
	acctID := firstNonEmpty(id, idForJWT(jwt))
	entry := Account{
		ID:           acctID,
		Label:        firstNonEmpty(label, acctID),
		JWT:          jwt,
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
		UserID:       userID,
		DeviceID:     randomUUID(),
		SessionSeed:  randomUUID(),
		ObtainedAt:   time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:    expiresAt,
	}
	for i := range rec.Accounts {
		if rec.Accounts[i].ID == acctID {
			entry.DeviceID = firstNonEmpty(rec.Accounts[i].DeviceID, entry.DeviceID)
			entry.SessionSeed = firstNonEmpty(rec.Accounts[i].SessionSeed, entry.SessionSeed)
			entry.Email = rec.Accounts[i].Email
			rec.Accounts[i] = entry
			break
		}
	}
	if !containsID(rec.Accounts, acctID) {
		rec.Accounts = append(rec.Accounts, entry)
	}
	if rec.Default == "" {
		rec.Default = acctID
	}
	_ = writeStore(rec)
	return entry
}

func containsID(accounts []Account, id string) bool {
	for i := range accounts {
		if accounts[i].ID == id {
			return true
		}
	}
	return false
}

// Remove forgets one account; the default moves to the first survivor.
func Remove(id string) bool {
	mu.Lock()
	defer mu.Unlock()
	rec := readStore()
	before := len(rec.Accounts)
	kept := rec.Accounts[:0]
	for _, a := range rec.Accounts {
		if a.ID != id {
			kept = append(kept, a)
		}
	}
	rec.Accounts = kept
	if rec.Default == id {
		if len(rec.Accounts) > 0 {
			rec.Default = rec.Accounts[0].ID
		} else {
			rec.Default = ""
		}
	}
	_ = writeStore(rec)
	return len(rec.Accounts) != before
}

// SetDefault pins one account as the rotation head.
func SetDefault(id string) bool {
	mu.Lock()
	defer mu.Unlock()
	rec := readStore()
	if !containsID(rec.Accounts, id) {
		return false
	}
	rec.Default = id
	_ = writeStore(rec)
	return true
}

// List returns every stored account (with secrets — internal use).
func List() []Account {
	mu.Lock()
	defer mu.Unlock()
	return readStore().Accounts
}

func cooledDown(id string, now time.Time) bool {
	st := runtime[id]
	return st != nil && st.cooldownUntil.After(now)
}

// Usable returns the accounts a new attempt may use, default first. Expired
// JWTs are skipped (and flagged) so rotation never parks on a dead token.
func Usable(exclude map[string]bool) []Account {
	mu.Lock()
	defer mu.Unlock()
	rec := readStore()
	now := time.Now()
	out := make([]Account, 0, len(rec.Accounts))
	ordered := append([]Account(nil), rec.Accounts...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].ID == rec.Default {
			return true
		}
		if ordered[j].ID == rec.Default {
			return false
		}
		return false
	})
	for _, a := range ordered {
		if exclude[a.ID] || a.NeedsReauth || cooledDown(a.ID, now) {
			continue
		}
		if a.ExpiresAt > 0 && a.ExpiresAt <= now.UnixMilli() {
			continue
		}
		out = append(out, a)
	}
	return out
}

// MarkCooldown parks an account for ms (the default when ms <= 0) and
// bumps its failure count. Live state only — a restart starts everyone
// healthy.
func MarkCooldown(id string, ms time.Duration) {
	mu.Lock()
	defer mu.Unlock()
	if ms <= 0 {
		ms = cooldownDefault()
	}
	st := runtime[id]
	if st == nil {
		st = &state{}
		runtime[id] = st
	}
	st.cooldownUntil = time.Now().Add(ms)
	st.failures++
}

// MarkReauth flags the account durably (persists in the file) and parks it
// indefinitely in live state.
func MarkReauth(id string) {
	mu.Lock()
	defer mu.Unlock()
	rec := readStore()
	for i := range rec.Accounts {
		if rec.Accounts[i].ID == id {
			rec.Accounts[i].NeedsReauth = true
			_ = writeStore(rec)
			break
		}
	}
	runtime[id] = &state{cooldownUntil: time.Now().Add(1 << 62)}
}

// ClearCooldown revives an account after a success, clearing both the live
// park and a persisted needsReauth flag.
func ClearCooldown(id string) {
	mu.Lock()
	defer mu.Unlock()
	if st := runtime[id]; st != nil {
		st.cooldownUntil = time.Time{}
		st.failures = 0
	}
	rec := readStore()
	for i := range rec.Accounts {
		if rec.Accounts[i].ID == id && rec.Accounts[i].NeedsReauth {
			rec.Accounts[i].NeedsReauth = false
			_ = writeStore(rec)
			break
		}
	}
}

// Summarize renders the non-secret ring view for /health and login --list.
func Summarize() []Summary {
	mu.Lock()
	defer mu.Unlock()
	rec := readStore()
	now := time.Now()
	out := make([]Summary, 0, len(rec.Accounts))
	for _, a := range rec.Accounts {
		s := Summary{
			ID:          a.ID,
			Label:       a.Label,
			Email:       a.Email,
			Default:     a.ID == rec.Default,
			HasRefresh:  a.RefreshToken != "",
			ExpiresAt:   a.ExpiresAt,
			Expired:     a.ExpiresAt > 0 && a.ExpiresAt <= now.UnixMilli(),
			NeedsReauth: a.NeedsReauth,
		}
		if st := runtime[a.ID]; st != nil && st.cooldownUntil.After(now) && st.cooldownUntil.Unix() < 1<<59 {
			s.CooldownUntil = st.cooldownUntil.UTC().Format(time.RFC3339)
		}
		out = append(out, s)
	}
	return out
}

// TryRefreshAccount attempts one best-effort JWT refresh for an account
// using its stored refresh token. On success the record is updated in place
// and the new expiry (unix ms) returned; on failure the account is marked
// needsReauth so rotation skips it, and the error is re-thrown.
func TryRefreshAccount(ctx context.Context, id string) (int64, error) {
	mu.Lock()
	rec := readStore()
	var entry *Account
	for i := range rec.Accounts {
		if rec.Accounts[i].ID == id {
			entry = &rec.Accounts[i]
			break
		}
	}
	mu.Unlock()
	if entry == nil {
		return 0, fmt.Errorf("account %s not found", id)
	}
	if entry.RefreshToken == "" {
		return 0, fmt.Errorf("account %s has no refresh token", id)
	}
	result, err := auth.RefreshPlanJWT(ctx, entry.RefreshToken)
	if err != nil {
		MarkReauth(id)
		return 0, err
	}
	claims, _ := auth.DecodeJWT(result.JWT)
	var expiresAt int64
	if claims != nil {
		if exp, ok := claims["exp"].(float64); ok {
			expiresAt = int64(exp) * 1000
		}
	}
	if expiresAt == 0 {
		expiresAt = time.Now().Add(24 * time.Hour).UnixMilli()
	}
	Upsert(entry.ID, entry.Label, result.JWT, result.RefreshToken, result.AccessToken, expiresAt)
	return expiresAt, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func envMs(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		var n int64
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

// ResetForTest drops the in-memory runtime state; used by the test suite
// to swap account files between checks.
func ResetForTest() {
	mu.Lock()
	defer mu.Unlock()
	runtime = map[string]*state{}
}
