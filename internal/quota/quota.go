// Package quota reads the start-plan grant readout ("today's balance").
//
//	GET /api/v1/zcode-plan/billing/balance?app_version=&platform=
//	    The panel endpoint: plans (definitions) AND balances (usage with the
//	    daily window period_start/period_end), each row self-describing
//	    (show_name, capabilities, grant units, priority, period). Requires a
//	    UUID X-Device-Mid header or it answers `3001 parameter error` —
//	    verified live 2026-10-30.
//	GET /api/v1/zcode-plan/billing/current
//	    Plan definitions WITHOUT usage; works with or without the device
//	    mid, used here as fallback when `balance` fails. Note: sending the
//	    control headers/params that `balance` needs makes `current` return
//	    an empty payload (verified 2026-10-30), so it gets bare auth only.
package quota

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/azrinaldi/zcode-bridge/internal/identity"
)

const (
	currentPath = "/api/v1/zcode-plan/billing/current"
	balancePath = "/api/v1/zcode-plan/billing/balance"
)

// Row is one entitlement's merged grant row (JSON keys mirror the JS
// bridge's readout shape so clients see the same fields).
type Row struct {
	Model          string `json:"model"`
	Models         []any  `json:"models"`
	EntitlementID  string `json:"entitlement_id"`
	Plan           string `json:"plan"`
	PlanName       string `json:"plan_name"`
	PlanID         string `json:"plan_id"`
	PlanStatus     any    `json:"plan_status"`
	EndsAt         any    `json:"ends_at"`
	Period         any    `json:"period"`
	PeriodStart    any    `json:"period_start"`
	PeriodEnd      any    `json:"period_end"`
	ExpiresAt      any    `json:"expires_at"`
	Priority       any    `json:"priority"`
	TotalUnits     any    `json:"total_units"`
	UsedUnits      any    `json:"used_units"`
	RemainingUnits any    `json:"remaining_units"`
	AvailableUnits any    `json:"available_units"`
	UnitType       any    `json:"unit_type"`
	Meter          any    `json:"meter"`
}

// ReadResult is the quota readout the /v1/quota route serves.
type ReadResult struct {
	OK         bool     `json:"ok"`
	Source     string   `json:"source"`
	ServerTime int64    `json:"server_time"`
	Plans      []any    `json:"plans"`
	Balances   []any    `json:"balances"`
	Rows       []Row    `json:"rows"`
	Errors     []string `json:"errors"`
	Account    string   `json:"account,omitempty"`
}

func balancePathWithQuery() string {
	return fmt.Sprintf("%s?app_version=%s&platform=%s",
		balancePath, identity.ResolveAppVersion(), identity.Platform())
}

// bareAuth is the bare auth face for `current`; the control face empties
// its payload.
func bareAuth(jwt string) map[string]string {
	return map[string]string{
		"accept":        "application/json",
		"authorization": "Bearer " + jwt,
	}
}

type envelope struct {
	OK     bool
	Code   any
	Msg    string
	Data   map[string]any
	Status int
}

func fetchEnvelope(ctx context.Context, path string, headers map[string]string) envelope {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, identity.Origin()+path, nil)
	if err != nil {
		return envelope{Msg: wrap(err)}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return envelope{Msg: wrap(err)}
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	var parsed struct {
		Code any            `json:"code"`
		Msg  string         `json:"msg"`
		Data map[string]any `json:"data"`
	}
	haveBody := json.Unmarshal(body, &parsed) == nil
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		msg := parsed.Msg
		if msg == "" {
			msg = string(body)
			if len(msg) > 160 {
				msg = msg[:160]
			}
		}
		return envelope{Status: res.StatusCode, Code: parsed.Code, Msg: msg}
	}
	if haveBody && codeNonZero(parsed.Code) {
		return envelope{Status: res.StatusCode, Code: parsed.Code, Msg: parsed.Msg}
	}
	return envelope{OK: true, Status: res.StatusCode, Code: parsed.Code, Msg: parsed.Msg, Data: parsed.Data}
}

func wrap(err error) string { return err.Error() }

func codeNonZero(code any) bool {
	switch v := code.(type) {
	case float64:
		return v != 0
	case int:
		return v != 0
	default:
		return false
	}
}

func capabilityModels(row map[string]any) []any {
	caps, _ := row["capabilities"].([]any)
	out := make([]any, 0, len(caps))
	for _, c := range caps {
		if s, ok := c.(string); ok && strings.HasPrefix(s, "model:") {
			out = append(out, strings.TrimPrefix(s, "model:"))
		}
	}
	return out
}

// finite mirrors Number.isFinite for the JSON numbers the gateways sends.
func finite(v any) any {
	if f, ok := v.(float64); ok && !isNaN(f) {
		return f
	}
	return nil
}

func isNaN(f float64) bool { return f != f }

func pick(preferred, fallback any) any {
	if preferred != nil {
		return preferred
	}
	return fallback
}

// ReadQuota reads the billing endpoints and merges them into
// per-entitlement rows. A model can be entitled by two plans (WEEKEND 500M +
// Start 5M flash); rows keep every grant, ByModel sums them.
func ReadQuota(ctx context.Context, jwt, deviceMid string) (*ReadResult, error) {
	if strings.TrimSpace(jwt) == "" {
		return nil, fmt.Errorf("no plan JWT: run login, or set ZCODE_PLAN_JWT")
	}
	ctl := identity.BuildControlHeaders(deviceMid)
	ctl["authorization"] = "Bearer " + jwt
	delete(ctl, "content-type")

	balance := fetchEnvelope(ctx, balancePathWithQuery(), ctl)
	var plans, balances []any
	var errs []string
	if balance.OK && balance.Data != nil {
		plans, _ = balance.Data["plans"].([]any)
		balances, _ = balance.Data["balances"].([]any)
	} else {
		msg := balance.Msg
		if msg == "" {
			msg = fmt.Sprintf("status %d", balance.Status)
		}
		errs = append(errs, "balance: "+msg)
	}
	// `current` as fallback: definitions only (no usage), bare headers.
	usedCurrent := false
	if len(plans) == 0 {
		current := fetchEnvelope(ctx, currentPath, bareAuth(jwt))
		if current.OK && current.Data != nil {
			if p, ok := current.Data["plans"].([]any); ok && len(p) > 0 {
				plans = p
				usedCurrent = true
			} else {
				errs = append(errs, "current: empty plan list")
			}
		} else {
			msg := current.Msg
			if msg == "" {
				msg = fmt.Sprintf("status %d", current.Status)
			}
			errs = append(errs, "current: "+msg)
		}
	}
	rows := mergeRows(plans, balances)
	serverTime := time.Now().Unix()
	if balance.OK && balance.Data != nil {
		if st, ok := balance.Data["server_time"].(float64); ok {
			serverTime = int64(st)
		}
	}
	source := "balance"
	if usedCurrent {
		source = "current"
	}
	return &ReadResult{
		OK:         len(rows) > 0,
		Source:     source,
		ServerTime: serverTime,
		Plans:      plans,
		Balances:   balances,
		Rows:       rows,
		Errors:     errs,
	}, nil
}

// mergeRows produces one row per entitlement, merged from whichever endpoint
// has data; entitlements defined but absent from the usage list still show
// their grant.
func mergeRows(plans, balances []any) []Row {
	type entMeta struct {
		plan map[string]any
		ent  map[string]any
	}
	entLookup := map[string]entMeta{}
	for _, p := range plans {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		ents, _ := pm["entitlements"].([]any)
		for _, e := range ents {
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			id, _ := em["entitlement_id"].(string)
			if id != "" {
				entLookup[id] = entMeta{plan: pm, ent: em}
			}
		}
	}

	var rows []Row
	for _, b := range balances {
		bm, ok := b.(map[string]any)
		if !ok {
			continue
		}
		id, _ := bm["entitlement_id"].(string)
		meta, hasMeta := entLookup[id]
		planID, _ := bm["plan_id"].(string)
		row := Row{
			Model:         firstNonEmpty(stringOf(bm["show_name"]), metaEntShowName(meta)),
			Models:        capabilityModels(bm),
			EntitlementID: id,
			Plan:          planID,
			PlanID:        planID,
		}
		if hasMeta {
			row.PlanName = stringOf(meta.plan["name"])
			row.PlanStatus = meta.plan["status"]
			row.EndsAt = meta.plan["ends_at"]
			row.Period = pick(bm["period"], meta.ent["period"])
			row.Priority = pick(bm["priority"], meta.ent["priority"])
			row.TotalUnits = pick(bm["total_units"], pick(meta.ent["grant_units"], nil))
			row.UnitType = pick(bm["unit_type"], meta.ent["unit_type"])
			row.Meter = pick(bm["meter"], meta.ent["meter"])
		} else {
			row.Period = bm["period"]
			row.Priority = bm["priority"]
			row.TotalUnits = bm["total_units"]
			row.UnitType = bm["unit_type"]
			row.Meter = bm["meter"]
		}
		row.PeriodStart = finite(bm["period_start"])
		row.PeriodEnd = finite(bm["period_end"])
		row.ExpiresAt = finite(bm["expires_at"])
		row.UsedUnits = finite(bm["used_units"])
		row.RemainingUnits = finite(bm["remaining_units"])
		row.AvailableUnits = finite(bm["available_units"])
		rows = append(rows, row)
	}
	// Entitlements defined but missing from the usage list: show the grant.
	for id, m := range entLookup {
		found := false
		for _, b := range balances {
			if bm, ok := b.(map[string]any); ok && stringOf(bm["entitlement_id"]) == id {
				found = true
				break
			}
		}
		if found {
			continue
		}
		planID, _ := m.plan["plan_id"].(string)
		rows = append(rows, Row{
			Model:         stringOf(m.ent["show_name"]),
			Models:        capabilityModels(m.ent),
			EntitlementID: id,
			Plan:          planID,
			PlanName:      stringOf(m.plan["name"]),
			PlanID:        planID,
			PlanStatus:    m.plan["status"],
			EndsAt:        m.plan["ends_at"],
			Period:        m.ent["period"],
			Priority:      pick(m.ent["priority"], m.plan["priority"]),
			TotalUnits:    pick(m.ent["grant_units"], nil),
			UnitType:      m.ent["unit_type"],
			Meter:         m.ent["meter"],
		})
	}
	return rows
}

func metaEntShowName(m struct {
	plan map[string]any
	ent  map[string]any
}) string {
	if m.ent == nil {
		return ""
	}
	return stringOf(m.ent["show_name"])
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ModelGrant is one model's summed grant across plans.
type ModelGrant struct {
	Model          string     `json:"model"`
	TotalUnits     float64    `json:"total_units"`
	UsedUnits      float64    `json:"used_units"`
	RemainingUnits float64    `json:"remaining_units"`
	Plans          []PlanPart `json:"plans"`
}

// PlanPart is one plan's contribution to a model's grant.
type PlanPart struct {
	Plan           string `json:"plan"`
	RemainingUnits any    `json:"remaining_units"`
	Period         any    `json:"period"`
	PeriodEnd      any    `json:"period_end"`
	EndsAt         any    `json:"ends_at"`
}

// ByModel groups rows per model id, summed across plans (what /v1/models
// shows).
func ByModel(rows []Row) map[string]*ModelGrant {
	out := map[string]*ModelGrant{}
	for _, r := range rows {
		ids := make([]string, 0, len(r.Models))
		for _, m := range r.Models {
			if s, ok := m.(string); ok {
				ids = append(ids, s)
			}
		}
		if len(ids) == 0 {
			ids = []string{strings.ToLower(r.Model)}
		}
		for _, id := range ids {
			g := out[id]
			if g == nil {
				g = &ModelGrant{Model: r.Model}
				out[id] = g
			}
			g.TotalUnits += num(r.TotalUnits)
			g.UsedUnits += num(r.UsedUnits)
			g.RemainingUnits += num(r.RemainingUnits)
			g.Plans = append(g.Plans, PlanPart{
				Plan:           firstNonEmpty(r.Plan, r.PlanID),
				RemainingUnits: r.RemainingUnits,
				Period:         r.Period,
				PeriodEnd:      r.PeriodEnd,
				EndsAt:         r.EndsAt,
			})
		}
	}
	return out
}

func num(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}
