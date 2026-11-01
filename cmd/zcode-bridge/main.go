// Command zcode-bridge is a local bridge onto the Z.ai start-plan
// inference lane. It accepts Anthropic and OpenAI wire formats, maps them
// onto the plan lane, rotates stored accounts, and reports plan quota.
//
//	zcode-bridge                 # serve on 127.0.0.1:20131
//	zcode-bridge login [--label work]
//	zcode-bridge login --list | --remove <id> | --set-default <id>
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/azrinaldi/zcode-bridge/internal/accounts"
	"github.com/azrinaldi/zcode-bridge/internal/auth"
	"github.com/azrinaldi/zcode-bridge/internal/identity"
	"github.com/azrinaldi/zcode-bridge/internal/server"
	"github.com/azrinaldi/zcode-bridge/internal/transport"
)

const version = "0.1.0"

func envInt(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "login" {
		runLogin(args[1:])
		return
	}
	if len(args) > 0 && (args[0] == "-v" || args[0] == "--version" || args[0] == "version") {
		fmt.Printf("zcode-bridge %s\n", version)
		return
	}
	serve()
}

func runLogin(args []string) {
	switch {
	case len(args) > 0 && args[0] == "--list":
		listAccounts()
	case len(args) > 1 && args[0] == "--remove":
		if accounts.Remove(args[1]) {
			fmt.Printf("removed %s\n", args[1])
		} else {
			fmt.Printf("no account %s\n", args[1])
		}
	case len(args) > 1 && args[0] == "--set-default":
		if accounts.SetDefault(args[1]) {
			fmt.Printf("default account is now %s\n", args[1])
		} else {
			fmt.Printf("no account %s\n", args[1])
		}
	case len(args) == 0 || args[0] == "--label":
		label := ""
		for i, a := range args {
			if a == "--label" && i+1 < len(args) {
				label = args[i+1]
			}
		}
		deviceLogin(label)
	default:
		fmt.Fprintln(os.Stderr, "usage: zcode-bridge login [--label <name>] | --list | --remove <id> | --set-default <id>")
		os.Exit(2)
	}
}

func listAccounts() {
	ring := accounts.Summarize()
	if len(ring) == 0 {
		fmt.Println("No accounts stored yet. Run `zcode-bridge login` and approve the URL.")
		return
	}
	for _, a := range ring {
		state := "ready"
		switch {
		case a.NeedsReauth:
			state = "NEEDS RE-AUTH"
		case a.Expired:
			state = "EXPIRED"
		case a.CooldownUntil != "":
			state = "cooling until " + a.CooldownUntil
		}
		marker := " "
		if a.Default {
			marker = "*"
		}
		extra := ""
		if a.HasRefresh {
			extra = "  (refreshable)"
		}
		fmt.Printf("  %s %-10s %-14s %s%s\n", marker, a.ID, a.Label, state, extra)
	}
}

func deviceLogin(label string) {
	ctx := context.Background()
	flow, err := auth.StartDeviceFlow(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "login failed: %v\n", err)
		os.Exit(1)
	}
	minutes := int(time.Until(flow.ExpiresAt).Minutes() + 0.5)
	if minutes < 1 {
		minutes = 1
	}
	fmt.Printf("Approve this URL in a browser where you are signed in to Z.ai (%d min limit):\n\n  %s\n\nWaiting for approval...\n",
		minutes, flow.AuthorizeURL)

	result, err := auth.PollDeviceFlow(ctx, flow)
	if err != nil {
		fmt.Fprintf(os.Stderr, "login failed: %v\n", err)
		os.Exit(1)
	}
	claims, _ := auth.DecodeJWT(result.JWT)
	var expiresAt int64
	if e, ok := claims["exp"].(float64); ok {
		expiresAt = int64(e) * 1000
	} else {
		expiresAt = time.Now().Add(24 * time.Hour).UnixMilli()
	}
	userID, _ := claims["user_id"].(string)
	if userID == "" {
		userID, _ = claims["sub"].(string)
	}
	// Upsert derives the stable account id from the JWT's user_id.
	tmp := accounts.Upsert("", label, result.JWT, result.RefreshToken, result.AccessToken, expiresAt)
	fmt.Printf("\nAuthorized. account %s (user %s) stored in %s\n",
		tmp.ID, orUnknown(userID), accounts.AccountsFile())
	if result.RefreshToken != "" {
		fmt.Println("refresh token stored; the bridge will try it on auth expiry (best effort).")
	} else {
		fmt.Println("no refresh token returned; re-run `zcode-bridge login` before the plan JWT expires.")
	}
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}

func serve() {
	host := strings.TrimSpace(os.Getenv("HOST"))
	if host == "" {
		host = "127.0.0.1"
	}
	cfg := server.Config{
		Port:        envInt("PORT", 20131),
		Host:        host,

		BridgeToken: strings.TrimSpace(os.Getenv("ZCODE_BRIDGE_TOKEN")),
	}
	server.Configure(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	jwtState := "MISSING (run: zcode-bridge login)"
	if auth.ResolvePlanJWT("") != "" {
		jwtState = "available"
	}
	midState := identity.ResolveDeviceMid()
	if midState == "" {
		midState = "MISSING"
	}
	authMode := "open (localhost)"
	if cfg.BridgeToken != "" {
		authMode = "bridge token required"
	}
	fmt.Printf("zcode-bridge %s listening on %s:%d\n  lane: zcode-plan/anthropic -> %s\n  plan jwt: %s\n  device mid: %s\n  auth: %s\n",
		version, cfg.Host, cfg.Port, transport.InferenceOrigin+transport.PlanAnthropicPath, jwtState, midState, authMode)

	// Background refresh: check every 15m (ZCODE_REFRESH_INTERVAL_MS),
	// refresh accounts expiring within 2h.
	refreshEvery := time.Duration(envInt("ZCODE_REFRESH_INTERVAL_MS", 15*60*1000)) * time.Millisecond
	go func() {
		ticker := time.NewTicker(refreshEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refreshExpiring(ctx)
			}
		}
	}()

	go func() {
		<-ctx.Done()
		// Give in-flight streams a moment, then leave.
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()

	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server: %v\n", err)
		os.Exit(1)
	}
}

func refreshExpiring(ctx context.Context) {
	const refreshBeforeExpiry = 2 * time.Hour
	now := time.Now().UnixMilli()
	for _, a := range accounts.List() {
		if a.RefreshToken == "" || a.ExpiresAt == 0 {
			continue
		}
		if time.Duration(a.ExpiresAt-now)*time.Millisecond > refreshBeforeExpiry {
			continue
		}
		fmt.Printf("[jwt-refresh] account %s (%s) expiring — refreshing\n", a.ID, a.Label)
		newExpiry, err := accounts.TryRefreshAccount(ctx, a.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[jwt-refresh] account %s refresh failed: %v — re-login required\n", a.ID, err)
			continue
		}
		fmt.Printf("[jwt-refresh] account %s refreshed, new expiry %s\n",
			a.ID, time.UnixMilli(newExpiry).UTC().Format(time.RFC3339))
	}
}
