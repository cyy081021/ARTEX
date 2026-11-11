package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func browserProfile(origins ...string) reverseRuntimeProfile {
	values := make([]any, len(origins))
	for i, origin := range origins {
		values[i] = origin
	}
	return reverseRuntimeProfile{ID: "fixture", Platform: "browser", Settings: map[string]any{"allowed_origins": values}}
}

func actionJSON(s string) json.RawMessage { return json.RawMessage(s) }

func TestReverseBrowserAllowedOrigins(t *testing.T) {
	profile := browserProfile("http://127.0.0.1:39451", "https://fixture.example")
	allowed, err := reverseBrowserAllowedOrigins(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"http://127.0.0.1:39451/fixture.html", "https://fixture.example/", "https://fixture.example/?page=2"} {
		if err := reverseBrowserCheckTarget(target, allowed); err != nil {
			t.Errorf("allowed target %q rejected: %v", target, err)
		}
	}
	for _, target := range []string{"http://127.0.0.1:39452/", "https://outside.example/", "file:///tmp/fixture.html", "https://user:pass@fixture.example/", "https://fixture.example/#fragment"} {
		if err := reverseBrowserCheckTarget(target, allowed); err == nil {
			t.Errorf("target %q unexpectedly allowed", target)
		}
	}
	if _, err := reverseBrowserAllowedOrigins(browserProfile("https://*.example.test")); err == nil {
		t.Fatal("wildcard origin was accepted")
	}
}

func TestReverseBrowserValidateActions(t *testing.T) {
	allowed, err := reverseBrowserAllowedOrigins(browserProfile("http://127.0.0.1:39451"))
	if err != nil {
		t.Fatal(err)
	}
	good := []json.RawMessage{
		actionJSON(`{"step_id":"fill-name","action":"fill","locator":{"kind":"role","role":"textbox","name":"Name"},"value":{"source":"literal","value":"fixture"}}`),
		actionJSON(`{"step_id":"submit","action":"click","locator":{"kind":"role","role":"button","name":"Submit"}}`),
		actionJSON(`{"step_id":"wait","action":"wait_for_timeout","duration_ms":50}`),
		actionJSON(`{"step_id":"route","action":"goto","destination":{"url":"http://127.0.0.1:39451/next","query":[]},"wait_until":"domcontentloaded"}`),
		actionJSON(`{"step_id":"request","action":"request","method":"GET","path":"/api/echo","headers":[]}`),
		actionJSON(`{"step_id":"credential","action":"fill","locator":{"kind":"css","selector":"#password"},"value":{"source":"secret","secret_id":"fixture-password"}}`),
		actionJSON(`{"step_id":"authenticated","action":"request","method":"GET","path":"/api","headers":[{"name":"Authorization","value":{"source":"local_storage","key":"token"}}]}`),
	}
	if err = reverseBrowserValidateActions(good, "http://127.0.0.1:39451/fixture.html", allowed); err != nil {
		t.Fatalf("valid canonical actions rejected: %v", err)
	}
	badCases := []struct {
		name    string
		start   string
		actions []json.RawMessage
	}{
		{"no actions", "http://127.0.0.1:39451/fixture.html", nil},
		{"foreign navigation", "http://127.0.0.1:39451/fixture.html", []json.RawMessage{actionJSON(`{"step_id":"x","action":"goto","destination":{"url":"http://127.0.0.2:39451/"}}`)}},
		{"absolute request URL", "http://127.0.0.1:39451/fixture.html", []json.RawMessage{actionJSON(`{"step_id":"x","action":"request","method":"GET","path":"https://outside.example/api","headers":[]}`)}},
		{"scheme-relative request URL", "http://127.0.0.1:39451/fixture.html", []json.RawMessage{actionJSON(`{"step_id":"x","action":"request","method":"GET","path":"//outside.example/api","headers":[]}`)}},
		{"unsupported javascript action", "http://127.0.0.1:39451/fixture.html", []json.RawMessage{actionJSON(`{"step_id":"x","action":"evaluate","expression":"fetch('https://outside.example')"}`)}},
		{"duplicate IDs", "http://127.0.0.1:39451/fixture.html", []json.RawMessage{actionJSON(`{"step_id":"x","action":"click"}`), actionJSON(`{"step_id":"x","action":"fill"}`)}},
		{"foreign start origin", "http://outside.example/", good[:1]},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := reverseBrowserValidateActions(tc.actions, tc.start, allowed); err == nil {
				t.Fatal("unsafe/invalid scenario was accepted")
			}
		})
	}
}

func TestDecodeReverseBrowserInputRejectsUnscopedFields(t *testing.T) {
	base := `{"artifact_id":1,"profile_id":"browser-fixture","start_url":"http://127.0.0.1:39451/fixture.html","duration_ms":500,"actions":[{"step_id":"wait","action":"wait_for_timeout","duration_ms":1}]}`
	if _, err := decodeReverseBrowserInput([]byte(base)); err != nil {
		t.Fatalf("valid scoped input rejected: %v", err)
	}
	for _, extra := range []string{",\"browser\":{\"mode\":\"connect\",\"cdp_endpoint\":\"ws://127.0.0.1\"}", ",\"path\":\"/tmp/arbitrary\"", ",\"env\":{\"TOKEN\":\"secret\"}", ",\"storage\":{}}"} {
		candidate := strings.TrimSuffix(base, "}") + extra
		if _, err := decodeReverseBrowserInput([]byte(candidate)); err == nil {
			t.Errorf("unscoped field was accepted: %s", extra)
		}
	}
}

func TestReverseBrowserDecodeResultHandlesJSONTextAndErrors(t *testing.T) {
	for _, raw := range []string{
		`{"isError":false,"structuredContent":{"operation":"capture_browser_scenario","normalized_result":{"steps":[{"step_id":"x"}]}}}`,
		`{"isError":false,"content":[{"type":"text","text":"{\"normalized_result\":{\"steps\":[]}}"}]}`,
	} {
		if _, err := reverseBrowserDecodeResult(json.RawMessage(raw)); err != nil {
			t.Fatalf("valid REA response rejected: %v", err)
		}
	}
	if _, err := reverseBrowserDecodeResult(json.RawMessage(`{"isError":true,"content":[{"type":"text","text":"failed"}]}`)); err == nil {
		t.Fatal("REA tool error was treated as success")
	}
	if _, err := reverseBrowserDecodeResult(json.RawMessage("not-json")); err == nil {
		t.Fatal("invalid REA response was treated as success")
	}
}
