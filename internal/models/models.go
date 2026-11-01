// Package models holds the model catalogue and the two-way request/response
// translation.
//
// Two client dialects are served from one upstream schema
// (anthropic-messages):
//
//	POST /v1/messages         Anthropic wire format (pass-through)
//	POST /v1/chat/completions OpenAI wire format (translated both ways)
//
// Translation is deliberately lossy only where the formats differ; nothing is
// invented, and unknown fields are dropped rather than forwarded blind.
package models

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// DefaultModel is the fallback when a request names no usable model.
const DefaultModel = "glm-5.3-flash"

type staticModel struct {
	ID              string `json:"id"`
	MaxOutputTokens int    `json:"max_output_tokens"`
}

var defaultModels = []staticModel{
	{ID: "glm-5.3", MaxOutputTokens: 131072},
	{ID: "glm-5.3-flash", MaxOutputTokens: 131072},
	{ID: "glm-5.2", MaxOutputTokens: 131072},
	{ID: "glm-5-turbo", MaxOutputTokens: 131072},
	{ID: "glm-4.6", MaxOutputTokens: 131072},
	{ID: "glm-4.5-air", MaxOutputTokens: 131072},
}

// knownModels are the lowercase canonical ids the catalogue ships with.
var knownModels = map[string]bool{
	"glm-5.3": true, "glm-5.3-flash": true, "glm-5.2": true,
	"glm-5-turbo": true, "glm-4.7": true, "glm-4.6": true,
	"glm-4.5": true, "glm-4.5-air": true,
}

var plausibleID = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{1,63}$`)

// NormalizeModel lowercases known models; passes through plausible ids
// lowercased. The plan gateway is case-sensitive on `model` (live A/B
// 2026-10-30: `GLM-5.3-Flash` -> ALB 502, `glm-5.3-flash` -> 200).
func NormalizeModel(model string) string {
	if strings.TrimSpace(model) == "" {
		return DefaultModel
	}
	lower := strings.ToLower(strings.TrimSpace(model))
	if knownModels[lower] {
		return lower
	}
	if plausibleID.MatchString(lower) {
		return lower
	}
	return DefaultModel
}

// ListModels is the static catalogue fallback (billing unreachable).
func ListModels() []staticModel { return defaultModels }

// ToAnthropicContent converts OpenAI content (string or parts[]) into
// Anthropic content: a string stays a string; parts become content blocks.
func ToAnthropicContent(content any) any {
	s, ok := content.(string)
	if ok {
		return s
	}
	parts, ok := content.([]any)
	if !ok {
		return ""
	}
	var blocks []map[string]any
	for _, part := range parts {
		m, ok := part.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := m["type"].(string)
		switch typ {
		case "text":
			if t, ok := m["text"].(string); ok {
				blocks = append(blocks, map[string]any{"type": "text", "text": t})
			}
		case "image_url":
			iu, _ := m["image_url"].(map[string]any)
			u, _ := iu["url"].(string)
			if u == "" {
				continue
			}
			if mt, data, isData := parseDataURL(u); isData {
				blocks = append(blocks, map[string]any{
					"type":   "image",
					"source": map[string]any{"type": "base64", "media_type": mt, "data": data},
				})
			} else {
				blocks = append(blocks, map[string]any{
					"type":   "image",
					"source": map[string]any{"type": "url", "url": u},
				})
			}
		}
	}
	if len(blocks) == 0 {
		return ""
	}
	return blocks
}

var dataURLRe = regexp.MustCompile(`^data:([^;]+);base64,(.*)$`)

func parseDataURL(u string) (mediaType, data string, ok bool) {
	m := dataURLRe.FindStringSubmatch(u)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// Block is a generic Anthropic content block (tool_result/tool_use/text).
type Block = map[string]any

// Message is a generic Anthropic wire message.
type Message struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

// OpenAIToAnthropic converts an OpenAI chat request into an Anthropic
// messages request. `system` is hoisted out of the message list because
// Anthropic models it as a top-level field; consecutive same-role turns are
// merged as the API requires. Returns the raw JSON body for the upstream.
func OpenAIToAnthropic(body map[string]any) map[string]any {
	messages, _ := body["messages"].([]any)
	var system []string
	var converted []map[string]any

	mergeOrAppend := func(role string, content any) {
		if len(converted) > 0 {
			last := converted[len(converted)-1]
			if last["role"] == role {
				prev := asBlockList(last["content"])
				next := asBlockList(content)
				last["content"] = append(prev, next...)
				return
			}
		}
		converted = append(converted, map[string]any{"role": role, "content": content})
	}

	for _, raw := range messages {
		msg, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		role, _ := msg["role"].(string)
		switch role {
		case "system", "developer":
			content := ToAnthropicContent(msg["content"])
			if text, isStr := content.(string); isStr {
				if text != "" {
					system = append(system, text)
				}
			} else if blocks, isArr := content.([]map[string]any); isArr {
				var texts []string
				for _, b := range blocks {
					if b["type"] == "text" {
						if t, ok := b["text"].(string); ok {
							texts = append(texts, t)
						}
					}
				}
				if len(texts) > 0 {
					system = append(system, strings.Join(texts, "\n"))
				}
			}
			continue
		case "tool":
			// OpenAI carries tool results as standalone role:"tool" messages;
			// Anthropic wants tool_result blocks inside a user turn.
			toolUseID, _ := msg["tool_call_id"].(string)
			if toolUseID == "" {
				toolUseID = "call_unknown"
			}
			content := stringifyContent(msg["content"])
			block := map[string]any{"type": "tool_result", "tool_use_id": toolUseID, "content": content}
			if len(converted) > 0 {
				last := converted[len(converted)-1]
				if last["role"] == "user" {
					if arr, ok := last["content"].([]any); ok && hasTypeAny(arr, "tool_result") {
						last["content"] = append(arr, block)
						continue
					}
				}
			}
			converted = append(converted, map[string]any{"role": "user", "content": []any{block}})
			continue
		case "user", "assistant":
			content := ToAnthropicContent(msg["content"])
			if role == "assistant" {
				if calls, ok := msg["tool_calls"].([]any); ok && len(calls) > 0 {
					var blocks []map[string]any
					switch c := content.(type) {
					case []map[string]any:
						blocks = append(blocks, c...)
					case string:
						if c != "" {
							blocks = append(blocks, map[string]any{"type": "text", "text": c})
						}
					}
					for _, callRaw := range calls {
						call, ok := callRaw.(map[string]any)
						if !ok {
							continue
						}
						if call["type"] != "function" {
							continue
						}
						fn, _ := call["function"].(map[string]any)
						if fn == nil {
							continue
						}
						name, _ := fn["name"].(string)
						input := map[string]any{}
						if raw, ok := fn["arguments"].(string); ok && strings.TrimSpace(raw) != "" {
							_ = json.Unmarshal([]byte(raw), &input)
						}
						blocks = append(blocks, map[string]any{
							"type": "tool_use", "id": call["id"], "name": name, "input": input,
						})
					}
					content = blocks
				}
			}
			mergeOrAppend(role, content)
		}
	}

	out := map[string]any{
		"model":      NormalizeModel(stringField(body, "model")),
		"max_tokens": maxTokensOf(body),
		"messages":   converted,
	}
	if len(system) > 0 {
		out["system"] = strings.Join(system, "\n\n")
	}
	if v, ok := numberField(body, "temperature"); ok {
		out["temperature"] = v
	}
	if v, ok := numberField(body, "top_p"); ok {
		out["top_p"] = v
	}
	switch stop := body["stop"].(type) {
	case []any:
		if len(stop) > 0 {
			out["stop_sequences"] = stop
		}
	case string:
		if stop != "" {
			out["stop_sequences"] = []any{stop}
		}
	}
	if streamTrue(body) {
		out["stream"] = true
	}
	if tools, ok := body["tools"].([]any); ok && len(tools) > 0 {
		var anthropicTools []map[string]any
		for _, t := range tools {
			tm, ok := t.(map[string]any)
			if !ok || tm["type"] != "function" {
				continue
			}
			fn, ok := tm["function"].(map[string]any)
			if !ok {
				continue
			}
			name, _ := fn["name"].(string)
			desc, _ := fn["description"].(string)
			schema, ok := fn["parameters"].(map[string]any)
			if !ok {
				schema = map[string]any{"type": "object", "properties": map[string]any{}}
			}
			entry := map[string]any{"name": name, "input_schema": schema}
			if desc != "" {
				entry["description"] = desc
			}
			anthropicTools = append(anthropicTools, entry)
		}
		if len(anthropicTools) > 0 {
			out["tools"] = anthropicTools
			switch choice := body["tool_choice"].(type) {
			case string:
				switch choice {
				case "auto":
					out["tool_choice"] = map[string]any{"type": "auto"}
				case "required":
					out["tool_choice"] = map[string]any{"type": "any"}
				case "none":
					out["tool_choice"] = map[string]any{"type": "none"}
				}
			case map[string]any:
				if choice["type"] == "function" {
					if fn, ok := choice["function"].(map[string]any); ok {
						if name, _ := fn["name"].(string); name != "" {
							out["tool_choice"] = map[string]any{"type": "tool", "name": name}
						}
					}
				}
			}
		}
	}
	return out
}

func hasType(blocks []map[string]any, typ string) bool {
	for _, b := range blocks {
		if b["type"] == typ {
			return true
		}
	}
	return false
}

// asBlockList normalizes message content into a []any of Anthropic blocks:
// bare strings become text blocks so merges never nest mismatched shapes.
func asBlockList(content any) []any {
	switch c := content.(type) {
	case []any:
		return c
	case []map[string]any:
		out := make([]any, 0, len(c))
		for _, b := range c {
			out = append(out, b)
		}
		return out
	case string:
		if c == "" {
			return nil
		}
		return []any{map[string]any{"type": "text", "text": c}}
	default:
		return []any{content}
	}
}

// hasTypeAny is hasType over an untyped block slice (tool_result turns are
// stored as []any so they merge with plain user turns).
func hasTypeAny(blocks []any, typ string) bool {
	for _, b := range blocks {
		if bm, ok := b.(map[string]any); ok && bm["type"] == typ {
			return true
		}
	}
	return false
}

func stringifyContent(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	raw, err := json.Marshal(v)
	if err != nil || strings.TrimSpace(string(raw)) == "" || string(raw) == "null" {
		return ""
	}
	return string(raw)
}

func stringField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func numberField(m map[string]any, key string) (float64, bool) {
	v, ok := m[key].(float64)
	return v, ok && !isNaN(v)
}

func maxTokensOf(body map[string]any) float64 {
	if v, ok := numberField(body, "max_tokens"); ok && v > 0 {
		return v
	}
	if v, ok := numberField(body, "max_completion_tokens"); ok && v > 0 {
		return v
	}
	return 4096
}

func streamTrue(body map[string]any) bool {
	b, _ := body["stream"].(bool)
	return b
}

func isNaN(f float64) bool { return f != f }

// ToOpenAIUsage converts Anthropic usage to OpenAI usage.
func ToOpenAIUsage(usage map[string]any) map[string]any {
	if usage == nil {
		return nil
	}
	num := func(k string) float64 {
		v, _ := usage[k].(float64)
		if v != v { // NaN
			return 0
		}
		return v
	}
	prompt := num("input_tokens")
	completion := num("output_tokens")
	return map[string]any{
		"prompt_tokens":     int64(prompt),
		"completion_tokens": int64(completion),
		"total_tokens":      int64(prompt + completion),
	}
}

// AnthropicToOpenAI converts an Anthropic non-streaming response into an
// OpenAI chat.completion.
func AnthropicToOpenAI(result map[string]any, model string) map[string]any {
	blocks, _ := result["content"].([]any)
	var text strings.Builder
	var toolCalls []map[string]any
	for _, b := range blocks {
		bm, ok := b.(map[string]any)
		if !ok {
			continue
		}
		switch bm["type"] {
		case "text":
			if t, ok := bm["text"].(string); ok {
				text.WriteString(t)
			}
		case "tool_use":
			name, _ := bm["name"].(string)
			id, _ := bm["id"].(string)
			args, err := json.Marshal(bm["input"])
			if err != nil {
				args = []byte("{}")
			}
			toolCalls = append(toolCalls, map[string]any{
				"id":       id,
				"type":     "function",
				"function": map[string]any{"name": name, "arguments": string(args)},
			})
		}
	}
	message := map[string]any{"role": "assistant"}
	if text.Len() > 0 {
		message["content"] = text.String()
	} else {
		message["content"] = nil
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	stopReason, _ := result["stop_reason"].(string)
	finish := "stop"
	switch stopReason {
	case "tool_use":
		finish = "tool_calls"
	case "max_tokens":
		finish = "length"
	}
	id, _ := result["id"].(string)
	if id == "" {
		id = "chatcmpl-" + fmtInt(time.Now().UnixNano()/1e6)
	}
	outModel := firstNonEmpty(model, stringField(result, "model"), "GLM-5.3")
	usage, _ := result["usage"].(map[string]any)
	return map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   outModel,
		"choices": []any{map[string]any{
			"index":         0,
			"message":       message,
			"finish_reason": finish,
		}},
		"usage": ToOpenAIUsage(usage),
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func fmtInt(n int64) string {
	// Base36-ish compact id, matching the JS shape loosely; uniqueness is
	// what matters.
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%36]
		n /= 36
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
