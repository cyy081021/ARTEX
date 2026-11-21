package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func campaignHTTPTestRequest(t *testing.T, s *Server, path string, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	s.reverseNativeRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authenticated {
		token, err := signJWT(s.jwtKey)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)
	return recorder
}
func TestNativeCampaignHTTPReadFeatureGate(t *testing.T) {
	s := &Server{jwtKey: []byte("campaign-http-test-key"), m: &Manager{}}
	for _, path := range []string{"/api/tasks/1/reverse/native/campaigns", "/api/tasks/1/reverse/native/campaigns/1", "/api/tasks/1/reverse/native/campaigns/1/manifest", "/api/tasks/1/reverse/native/campaigns/1/attempts", "/api/tasks/1/reverse/native/campaigns/1/checkpoints"} {
		if r := campaignHTTPTestRequest(t, s, path, false); r.Code != 401 {
			t.Fatalf("unauthenticated %s: %d %s", path, r.Code, r.Body)
		}
		if r := campaignHTTPTestRequest(t, s, path, true); r.Code != 409 || !strings.Contains(r.Body.String(), "environment_incompatible") {
			t.Fatalf("disabled %s: %d %s", path, r.Code, r.Body)
		}
	}
	if s.campaign != nil {
		t.Fatal("read initialized runtime")
	}
}
func TestNativeCampaignHTTPStrictQuery(t *testing.T) {
	for _, raw := range []string{"limit=1&limit=2", "unknown=1", "limit=", "limit=1;before_id=2", "%zz=1"} {
		r := httptest.NewRequest("GET", "/?"+raw, nil)
		if _, err := nativeCampaignHTTPQuery(r, "limit", "before_id"); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"", "-1", "+1", "1.0", "1e2", " 1", "null", "9223372036854775808"} {
		if _, err := nativeCampaignHTTPInteger(raw, 0, 1<<63-1); err == nil {
			t.Fatalf("accepted integer %q", raw)
		}
	}
}
func TestNativeCampaignHTTPReadDTOs(t *testing.T) {
	f := newT4AFixture(t, "http-read")
	c := f.createCampaign("first")
	c2 := f.createCampaign("second")
	s := &Server{jwtKey: []byte("campaign-http-test-key"), m: &Manager{pg: f.pg}, campaign: &nativeCampaignRuntime{service: f.service, manager: f.manager}}
	base := fmt.Sprintf("/api/tasks/%d/reverse/native/campaigns", f.task.ID)
	// GET must remain usable even when scheduling/reconciliation is unavailable.
	s.campaignInitErr = fmt.Errorf("private host path /secret/should-not-leak")
	r := campaignHTTPTestRequest(t, s, base+"?limit=1", true)
	if r.Code != 200 {
		t.Fatalf("list %d %s", r.Code, r.Body)
	}
	var page struct {
		Campaigns []struct {
			ID int64 `json:"id"`
		} `json:"campaigns"`
		Next int64 `json:"next_before_id"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Campaigns) != 1 || page.Campaigns[0].ID != c2.ID || page.Next != c2.ID {
		t.Fatalf("page: %s", r.Body)
	}
	r = campaignHTTPTestRequest(t, s, fmt.Sprintf("%s?limit=1&before_id=%d", base, page.Next), true)
	if r.Code != 200 || !strings.Contains(r.Body.String(), fmt.Sprintf(`"id":%d`, c.ID)) {
		t.Fatalf("next page: %d %s", r.Code, r.Body)
	}
	status := fmt.Sprintf("%s/%d", base, c.ID)
	if _, err := f.pg.ExecContext(context.Background(), `UPDATE native_campaigns SET last_error_code='engine_error',last_error_message='/private/secret' WHERE id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "?include_events=true", "?include_events=false"} {
		r = campaignHTTPTestRequest(t, s, status+suffix, true)
		if r.Code != 200 {
			t.Fatalf("status %d %s", r.Code, r.Body)
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		_, hasEvents := body["events"]
		if hasEvents != (suffix == "?include_events=true") {
			t.Fatalf("events: %s", r.Body)
		}
		for _, key := range []string{"current_attempt", "latest_checkpoint", "latest_evidence"} {
			if string(body[key]) != "null" {
				t.Fatalf("missing %s not null: %s", key, r.Body)
			}
		}
		for _, secret := range []string{"/private/secret", "/secret/should-not-leak", `"spec":`, `"owned_resources":`, `"lease_instance":`} {
			if strings.Contains(r.Body.String(), secret) {
				t.Fatalf("leaked %q", secret)
			}
		}
	}
	for _, suffix := range []string{"?include_events=1", "?include_events=true&include_events=false", "?max_entries=1"} {
		if r = campaignHTTPTestRequest(t, s, status+suffix, true); r.Code != 400 {
			t.Fatalf("bad query accepted: %s", r.Body)
		}
	}
	for _, suffix := range []string{"?limit=0", "?limit=101", "?before_id=-1", "?limit=1.0", "?limit=1&limit=2"} {
		if r = campaignHTTPTestRequest(t, s, base+suffix, true); r.Code != 400 {
			t.Fatalf("bad list query accepted: %s", r.Body)
		}
	}
	r = campaignHTTPTestRequest(t, s, status+"/manifest", true)
	if r.Code != 409 || !strings.Contains(r.Body.String(), "no_checkpoint") {
		t.Fatalf("missing checkpoint: %d %s", r.Code, r.Body)
	}
	other := newT4AFixture(t, "http-other")
	oc := other.createCampaign("other")
	r = campaignHTTPTestRequest(t, s, fmt.Sprintf("%s/%d", base, oc.ID), true)
	if r.Code != 404 {
		t.Fatalf("cross task: %d %s", r.Code, r.Body)
	}
	if f.factory.Count() != 0 {
		t.Fatal("read started runner")
	}
}
func TestNativeCampaignHTTPPayloadBoundary(t *testing.T) {
	raw := json.RawMessage(`{"charged_budget_ms":12,"reason":"/secret/path","owned_resources":{"root":"/secret"},"attempt_id":2}`)
	payload := nativeCampaignHTTPEventPayload(raw)
	b, _ := json.Marshal(payload)
	if strings.Contains(string(b), "secret") || payload["charged_budget_ms"] != int64(12) {
		t.Fatalf("payload %s", b)
	}
	if len(nativeCampaignHTTPEventPayload(json.RawMessage(strings.Repeat("x", 4097)))) != 0 {
		t.Fatal("oversize exported")
	}
	c := &db.NativeCampaign{Spec: json.RawMessage(`{"secret":"payload"}`)}
	b, _ = json.Marshal(nativeCampaignHTTPSummary(c))
	if strings.Contains(string(b), "payload") {
		t.Fatal("spec leaked")
	}
}

func TestNativeCampaignHTTPFreeTextNotPublic(t *testing.T) {
	secret := "/private/host/path"
	c := &db.NativeCampaign{LastErrorCode: &secret, LastErrorMessage: &secret, TerminationReason: &secret}
	b, _ := json.Marshal(nativeCampaignHTTPSummary(c))
	if strings.Contains(string(b), secret) {
		t.Fatalf("campaign leaks: %s", b)
	}
	a := &db.NativeCampaignAttempt{TerminationReason: &secret, HoldReason: &secret, OwnedResources: json.RawMessage(`{"root":"/private/host/path"}`)}
	b, _ = json.Marshal(nativeCampaignHTTPAttempt(a))
	if strings.Contains(string(b), secret) {
		t.Fatalf("attempt leaks: %s", b)
	}
}

// This is a DB-read HTTP fixture, not a claim that CAS files were persisted.
// The tested read route must not read those files or invoke a loader.
func TestNativeCampaignHTTPManifestBoundsAndOwnership(t *testing.T) {
	f := newT4AFixture(t, "http-manifest")
	c, run := f.startOneRun(t, "manifest")
	records := make([]nativeCampaignCheckpointRecord, 512)
	entries := make([]db.NativeCampaignEntryInput, 512)
	var total int64
	for i := range records {
		data := []byte(fmt.Sprintf("seed-%04d", i))
		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])
		records[i] = nativeCampaignCheckpointRecord{SHA256: hash, Length: len(data), StorageKey: nativeCampaignCheckpointStorageKey(f.task.ID, hash), SourceType: "queue", SourceRef: fmt.Sprintf("id:%06d", i)}
		entries[i] = db.NativeCampaignEntryInput{Ordinal: i, SHA256: hash, Length: int64(len(data)), StorageKey: records[i].StorageKey, SourceType: "queue", SourceRef: records[i].SourceRef}
		total += int64(len(data))
	}
	canonical, err := nativeCampaignCanonicalManifest(f.task.ID, c.ID, run.attemptID, records)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(canonical)
	cp, err := f.pg.CommitVerifiedNativeCampaignCheckpoint(context.Background(), db.NativeCampaignCheckpointCommit{NativeCampaignLeaseIdentity: run.identity(), Manifest: db.NativeCampaignManifestInput{TaskID: f.task.ID, CampaignID: c.ID, AttemptID: run.attemptID, ManifestSHA256: hex.EncodeToString(hash[:]), EntryCount: 512, TotalBytes: total, Entries: entries}})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{jwtKey: []byte("campaign-http-test-key"), m: &Manager{pg: f.pg}, campaign: &nativeCampaignRuntime{service: f.service, manager: f.manager}}
	path := fmt.Sprintf("/api/tasks/%d/reverse/native/campaigns/%d/manifest?checkpoint_id=%d", f.task.ID, c.ID, cp.ID)
	for _, tc := range []struct {
		suffix string
		count  int
	}{{"", 64}, {"&max_entries=256", 256}, {"&max_entries=1", 1}} {
		r := campaignHTTPTestRequest(t, s, path+tc.suffix, true)
		if r.Code != 200 {
			t.Fatalf("manifest %d %s", r.Code, r.Body)
		}
		var dto struct {
			EntryCount int              `json:"entry_count"`
			Entries    []map[string]any `json:"entries"`
			Preview    bool             `json:"preview_truncated"`
			Total      int64            `json:"total_bytes"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &dto); err != nil {
			t.Fatal(err)
		}
		if dto.EntryCount != 512 || len(dto.Entries) != tc.count || !dto.Preview || dto.Total != total {
			t.Fatalf("incorrect preview: %s", r.Body)
		}
	}
	other := f.createCampaign("same-task-other")
	r := campaignHTTPTestRequest(t, s, fmt.Sprintf("/api/tasks/%d/reverse/native/campaigns/%d/manifest?checkpoint_id=%d", f.task.ID, other.ID, cp.ID), true)
	if r.Code != 404 {
		t.Fatalf("cross campaign checkpoint: %d %s", r.Code, r.Body)
	}

}
func TestNativeCampaignHTTPRejectsNonReverseTask(t *testing.T) {
	f := newT4AFixture(t, "http-task-kind")
	// A real ordinary task, not a forged task ID.
	task, err := f.pg.CreateTaskWithOptions("ordinary HTTP test", "not reverse", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID) })
	s := &Server{jwtKey: []byte("campaign-http-test-key"), m: &Manager{pg: f.pg}, campaign: &nativeCampaignRuntime{service: f.service}}
	r := campaignHTTPTestRequest(t, s, fmt.Sprintf("/api/tasks/%d/reverse/native/campaigns", task.ID), true)
	if r.Code != 404 {
		t.Fatalf("nonreverse: %d %s", r.Code, r.Body)
	}
}

func TestNativeCampaignHTTPManifestRejectsUnsafeStoredSource(t *testing.T) {
	f := newT4AFixture(t, "http-unsafe-source")
	c, run := f.startOneRun(t, "unsafe-source")
	digest := strings.Repeat("a", 64)
	// The legacy metadata API permits source_ref text; create a separate immutable
	// fixture at its insertion boundary, never disable/update the immutable trigger.
	cp, err := f.pg.CommitVerifiedNativeCampaignCheckpoint(context.Background(), db.NativeCampaignCheckpointCommit{NativeCampaignLeaseIdentity: run.identity(), Manifest: db.NativeCampaignManifestInput{TaskID: f.task.ID, CampaignID: c.ID, AttemptID: run.attemptID, ManifestSHA256: strings.Repeat("b", 64), EntryCount: 1, TotalBytes: 1, Entries: []db.NativeCampaignEntryInput{{Ordinal: 0, SHA256: digest, Length: 1, StorageKey: nativeCampaignCheckpointStorageKey(f.task.ID, digest), SourceType: "queue", SourceRef: "/private/host/source"}}}})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{jwtKey: []byte("campaign-http-test-key"), m: &Manager{pg: f.pg}, campaign: &nativeCampaignRuntime{service: f.service}}
	path := fmt.Sprintf("/api/tasks/%d/reverse/native/campaigns/%d/manifest?checkpoint_id=%d", f.task.ID, c.ID, cp.ID)
	r := campaignHTTPTestRequest(t, s, path, true)
	if r.Code != 500 || strings.Contains(r.Body.String(), "/private/") {
		t.Fatalf("unsafe source ref: %d %s", r.Code, r.Body)
	}
}

func campaignHTTPPost(t *testing.T, s *Server, taskID int64, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	s.reverseNativeRoutes(mux)
	r := httptest.NewRequest("POST", fmt.Sprintf("/api/tasks/%d/reverse/native/campaign", taskID), strings.NewReader(body))
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	mux.ServeHTTP(out, r)
	return out
}
func TestNativeCampaignHTTPStrictActions(t *testing.T) {
	for _, body := range []string{
		`null`, `[]`, `{"action":"validate","action":"start","campaign_id":1}`, `{"action":"validate","campaign_id":1} {}`,
		`{"action":"validate","campaign_id":1,"request_id":"unused"}`, `{"action":"start","campaign_id":1,"reason":"unused"}`,
		`{"action":"create","seeds":[{"sha256":"a","sha256":"b","data_base64":"Wg=="}]}`,
	} {
		if _, _, err := nativeCampaignHTTPActionBody(httptest.NewRequest("POST", "/", strings.NewReader(body))); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	base := map[string]json.RawMessage{"total_budget_ms": json.RawMessage(`600000`), "seeds": json.RawMessage(`[{"sha256":"bbeebd879e1dff6918546dc0c179fdde505f2a21591c9a9c96e36b054ec5af83","data_base64":"Wg=="}]`)}
	for _, raw := range []string{`null`, `"6000"`, `6000.0`, `6e3`, `-1`, `9223372036854775808`} {
		copy := map[string]json.RawMessage{}
		for k, v := range base {
			copy[k] = v
		}
		copy["default_attempt_budget_ms"] = json.RawMessage(raw)
		if _, _, err := nativeCampaignHTTPInitialSpec(copy); err == nil {
			t.Fatalf("accepted budget %s", raw)
		}
	}
	for _, raw := range []string{`null`, `[]`, `[{"sha256":"bad","data_base64":"Wg=="}]`, `[{"sha256":"bbeebd879e1dff6918546dc0c179fdde505f2a21591c9a9c96e36b054ec5af83","data_base64":"Wg==","source_ref":"/secret"}]`, `[{"sha256":"bbeebd879e1dff6918546dc0c179fdde505f2a21591c9a9c96e36b054ec5af83","data_base64":"Wg==\n"}]`} {
		copy := map[string]json.RawMessage{}
		for k, v := range base {
			copy[k] = v
		}
		copy["seeds"] = json.RawMessage(raw)
		if _, _, err := nativeCampaignHTTPInitialSpec(copy); err == nil {
			t.Fatalf("accepted seed %s", raw)
		}
	}
}
func TestNativeCampaignHTTPMutationFlow(t *testing.T) {
	f := newT4AFixture(t, "http-mutations")
	s := &Server{jwtKey: []byte("campaign-http-test-key"), m: &Manager{pg: f.pg}, campaign: &nativeCampaignRuntime{service: f.service, manager: f.manager}}
	create := fmt.Sprintf(`{"action":"create","request_id":"http-create","artifact_id":%d,"profile_id":%q,"seeds":[{"sha256":"bbeebd879e1dff6918546dc0c179fdde505f2a21591c9a9c96e36b054ec5af83","data_base64":"Wg=="}],"total_budget_ms":600000}`, f.artifact.ID, f.profile.ID)
	r := campaignHTTPPost(t, s, f.task.ID, create)
	if r.Code != 201 {
		t.Fatalf("create %d %s", r.Code, r.Body)
	}
	if f.images.Calls() != 0 || f.factory.Count() != 0 || f.attemptCount() != 0 {
		t.Fatal("draft executed capability")
	}
	var created struct {
		Campaign db.NativeCampaign `json:"campaign"`
		Replayed bool              `json:"replayed"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	id := created.Campaign.ID
	if id <= 0 || created.Campaign.ImageID != nil || strings.Contains(r.Body.String(), `"spec":`) {
		t.Fatalf("create DTO %s", r.Body)
	}
	r = campaignHTTPPost(t, s, f.task.ID, create)
	if r.Code != 201 || !strings.Contains(r.Body.String(), `"replayed":true`) {
		t.Fatalf("replay %d %s", r.Code, r.Body)
	}
	r = campaignHTTPPost(t, s, f.task.ID, strings.Replace(create, `"total_budget_ms":600000`, `"total_budget_ms":600001`, 1))
	if r.Code != 409 || !strings.Contains(r.Body.String(), "idempotency_conflict") {
		t.Fatalf("conflict %d %s", r.Code, r.Body)
	}
	r = campaignHTTPPost(t, s, f.task.ID, fmt.Sprintf(`{"action":"validate","campaign_id":%d}`, id))
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"can_start":true`) {
		t.Fatalf("validate %d %s", r.Code, r.Body)
	}
	start := fmt.Sprintf(`{"action":"start","campaign_id":%d,"request_id":"http-start","expected_state_version":1}`, id)
	r = campaignHTTPPost(t, s, f.task.ID, start)
	if r.Code != 202 {
		t.Fatalf("start %d %s", r.Code, r.Body)
	}
	if f.factory.Count() != 0 || f.attemptCount() != 0 {
		t.Fatal("HTTP start must only queue")
	}
	stale := fmt.Sprintf(`{"action":"pause","campaign_id":%d,"request_id":"http-pause-stale","expected_state_version":1}`, id)
	r = campaignHTTPPost(t, s, f.task.ID, stale)
	if r.Code != 409 || !strings.Contains(r.Body.String(), "state_conflict") {
		t.Fatalf("stale pause %d %s", r.Code, r.Body)
	}
	r = campaignHTTPPost(t, s, f.task.ID, fmt.Sprintf(`{"action":"pause","campaign_id":%d,"request_id":"http-pause","expected_state_version":2}`, id))
	if r.Code != 200 {
		t.Fatalf("pause %d %s", r.Code, r.Body)
	}
	r = campaignHTTPPost(t, s, f.task.ID, start)
	if r.Code != 202 || !strings.Contains(r.Body.String(), `"state":"queued"`) || !strings.Contains(r.Body.String(), `"state_version":2`) {
		t.Fatalf("snapshot replay %d %s", r.Code, r.Body)
	}
	r = campaignHTTPPost(t, s, f.task.ID, fmt.Sprintf(`{"action":"resume","campaign_id":%d,"request_id":"http-resume","expected_state_version":3}`, id))
	if r.Code != 202 {
		t.Fatalf("resume %d %s", r.Code, r.Body)
	}
	f.images.mu.Lock()
	f.images.err = fmt.Errorf("/host/private/image-error")
	f.images.mu.Unlock()
	before := f.images.Calls()
	r = campaignHTTPPost(t, s, f.task.ID, fmt.Sprintf(`{"action":"cancel","campaign_id":%d,"request_id":"http-cancel","expected_state_version":4}`, id))
	if r.Code != 200 {
		t.Fatalf("cancel %d %s", r.Code, r.Body)
	}
	if f.images.Calls() != before {
		t.Fatal("cancel inspected image")
	}
	r = campaignHTTPPost(t, s, f.task.ID, fmt.Sprintf(`{"action":"validate","campaign_id":%d}`, id))
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"can_start":false`) || !strings.Contains(r.Body.String(), `"can_resume":false`) || strings.Contains(r.Body.String(), "/host/") {
		t.Fatalf("terminal diagnostics %d %s", r.Code, r.Body)
	}
	for _, value := range []string{`null`, `"1"`, `1.0`, `1e0`, `0`, `-1`, `9223372036854775808`} {
		r = campaignHTTPPost(t, s, f.task.ID, fmt.Sprintf(`{"action":"pause","campaign_id":%d,"request_id":"invalid-version","expected_state_version":%s}`, id, value))
		if r.Code != 400 {
			t.Fatalf("invalid CAS %s: %d %s", value, r.Code, r.Body)
		}
	}
}

func TestNativeCampaignHTTPAuthorityAndZeroMutation(t *testing.T) {
	f := newT4AFixture(t, "http-authority")
	c := f.createCampaign("owned")
	other := newT4AFixture(t, "http-cross")
	oc := other.createCampaign("foreign")
	s := &Server{jwtKey: []byte("campaign-http-test-key"), m: &Manager{pg: f.pg}, campaign: &nativeCampaignRuntime{service: f.service}}
	count := func() int {
		var n int
		if err := f.pg.QueryRow(`SELECT count(*) FROM native_campaign_requests WHERE task_id=$1`, f.task.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()
	for _, action := range []string{"validate", "start", "pause", "cancel", "resume"} {
		body := fmt.Sprintf(`{"action":%q,"campaign_id":%d`, action, oc.ID)
		if action != "validate" {
			body += fmt.Sprintf(`,"request_id":"cross-%s","expected_state_version":1`, action)
		}
		body += "}"
		r := campaignHTTPPost(t, s, f.task.ID, body)
		if r.Code != 404 {
			t.Fatalf("cross %s: %d %s", action, r.Code, r.Body)
		}
	}
	team, err := f.pg.CreateTeam(context.Background(), "campaign-http-team")
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.pg.CreateTeamMember(context.Background(), team.ID, "member", "unused-test-hash")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": fmt.Sprintf("team:%d:%d", team.ID, member.ID)}).SignedString(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.reverseNativeRoutes(mux)
	for _, method := range []string{"GET", "POST"} {
		path := fmt.Sprintf("/api/tasks/%d/reverse/native/campaigns", f.task.ID)
		if method == "POST" {
			path = strings.TrimSuffix(path, "s")
		}
		for _, auth := range []string{"", token} {
			req := httptest.NewRequest(method, path, strings.NewReader(fmt.Sprintf(`{"action":"start","campaign_id":%d,"request_id":"unauthorized","expected_state_version":1}`, c.ID)))
			if auth != "" {
				req.Header.Set("Authorization", "Bearer "+auth)
			}
			r := httptest.NewRecorder()
			mux.ServeHTTP(r, req)
			want := 401
			if auth != "" {
				want = 403
			}
			if r.Code != want {
				t.Fatalf("%s auth %d %s", method, r.Code, r.Body)
			}
		}
	}
	if count() != before || f.factory.Count() != 0 || f.attemptCount() != 0 {
		t.Fatal("rejected request mutated or executed")
	}
	if got := f.reloadCampaign(c); got.StateVersion != c.StateVersion || got.State != c.State {
		t.Fatal("rejected request changed campaign")
	}
	large := strings.Repeat("x", db.NativeCampaignSpecBytes+1)
	r := campaignHTTPPost(t, s, f.task.ID, large)
	if r.Code != 413 || !strings.Contains(r.Body.String(), "quota_exceeded") {
		t.Fatalf("body size %d %s", r.Code, r.Body)
	}
}
func TestNativeCampaignHTTPConcurrentCAS(t *testing.T) {
	for _, same := range []bool{false, true} {
		t.Run(fmt.Sprintf("same_id_%t", same), func(t *testing.T) {
			f := newT4AFixture(t, "http-concurrent")
			c := f.createCampaign("parallel")
			s := &Server{jwtKey: []byte("campaign-http-test-key"), m: &Manager{pg: f.pg}, campaign: &nativeCampaignRuntime{service: f.service}}
			run := func(action string, version int64) {
				gate := make(chan struct{})
				results := make(chan *httptest.ResponseRecorder, 2)
				var wg sync.WaitGroup
				for i := 0; i < 2; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						request := fmt.Sprintf("parallel-%s-%d", action, i)
						if same {
							request = "parallel-" + action
						}
						<-gate
						results <- campaignHTTPPost(t, s, f.task.ID, fmt.Sprintf(`{"action":%q,"campaign_id":%d,"request_id":%q,"expected_state_version":%d}`, action, c.ID, request, version))
					}(i)
				}
				close(gate)
				wg.Wait()
				close(results)
				success, conflict := 0, 0
				for r := range results {
					if r.Code == 202 {
						success++
					} else if r.Code == 409 && strings.Contains(r.Body.String(), "state_conflict") {
						conflict++
					} else {
						t.Fatalf("parallel %s %d %s", action, r.Code, r.Body)
					}
				}
				if same && (success != 2 || conflict != 0) || !same && (success != 1 || conflict != 1) {
					t.Fatalf("parallel counts %d %d", success, conflict)
				}
			}
			run("start", 1)
			r := campaignHTTPPost(t, s, f.task.ID, fmt.Sprintf(`{"action":"pause","campaign_id":%d,"request_id":"pause-between","expected_state_version":2}`, c.ID))
			if r.Code != 200 {
				t.Fatalf("pause %d %s", r.Code, r.Body)
			}
			run("resume", 3)
			got := f.reloadCampaign(c)
			if got.StateVersion != 4 || got.State != "queued" || f.attemptCount() != 0 {
				t.Fatalf("duplicate CAS changed state: %+v", got)
			}
			var events int
			if err := f.pg.QueryRow(`SELECT count(*) FROM native_campaign_events WHERE campaign_id=$1 AND kind IN ('campaign.queued','campaign.resume_queued')`, c.ID).Scan(&events); err != nil {
				t.Fatal(err)
			}
			if events != 2 {
				t.Fatalf("duplicate queue events %d", events)
			}
			if _, err := f.pg.Exec(`UPDATE reverse_runtime_policies SET enabled=false WHERE task_id=$1`, f.task.ID); err != nil {
				t.Fatal(err)
			}
			before := f.images.Calls()
			r = campaignHTTPPost(t, s, f.task.ID, fmt.Sprintf(`{"action":"cancel","campaign_id":%d,"request_id":"cancel-revoked","expected_state_version":4}`, c.ID))
			if r.Code != 200 || f.images.Calls() != before {
				t.Fatalf("revoked cancel inspected or failed: %d %s", r.Code, r.Body)
			}
		})
	}
}

func TestNativeCampaignHTTPOnlyFencedPublishedEvidence(t *testing.T) {
	f := newT4AFixture(t, "http-evidence-publication")
	c, run := f.startOneRun(t, "evidence-publication")
	s := &Server{jwtKey: []byte("campaign-http-test-key"), m: &Manager{pg: f.pg}, campaign: &nativeCampaignRuntime{service: f.service}}
	prepare := func(kind string) *db.NativeCampaignEvidence {
		e, err := f.pg.CreateNativeCampaignEvidence(context.Background(), db.NativeCampaignEvidenceInput{TaskID: f.task.ID, CampaignID: c.ID, AttemptID: run.attemptID, Kind: kind, ResultPath: fmt.Sprintf("tasks/%d/reverse/campaigns/%d/%s.json", f.task.ID, c.ID, kind), SHA256: strings.Repeat("a", 64), Observation: json.RawMessage(`{"authority":"candidate-only"}`)})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	orphan := prepare("interrupt")
	identity := run.identity()
	_, err := f.service.Finalize(context.Background(), db.NativeCampaignFinalizeCommand{TaskID: f.task.ID, CampaignID: c.ID, AttemptID: run.attemptID, FencingToken: identity.FencingToken + 1, LeaseOwner: identity.LeaseOwner, LeaseInstance: identity.LeaseInstance, TargetState: "failed", CleanupStatus: "unknown", Phase: "finalize", EvidenceID: orphan.ID, TerminationReason: "engine_error", ActorKind: "admin"})
	f.expectErrorCode(err, "lease_lost")
	path := fmt.Sprintf("/api/tasks/%d/reverse/native/campaigns/%d", f.task.ID, c.ID)
	r := campaignHTTPTestRequest(t, s, path, true)
	if r.Code != 200 {
		t.Fatalf("status %d %s", r.Code, r.Body)
	}
	var body struct {
		Latest *struct {
			ID        int64  `json:"id"`
			Authority string `json:"authority"`
		} `json:"latest_evidence"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Latest != nil {
		t.Fatalf("failed CAS published: %s", r.Body)
	}
	a, err := f.pg.NativeCampaignAttempt(context.Background(), f.task.ID, run.attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if !a.ResourceHold || a.EvidenceManifestID != nil {
		t.Fatalf("failed CAS mutated ownership: %+v", a)
	}
	// Normal Manager finalization publishes its own attempt_final row.
	f.driveFinal(t, run.attemptID, "completed", t4aVerifiedCleanup())
	a, err = f.pg.NativeCampaignAttempt(context.Background(), f.task.ID, run.attemptID)
	if err != nil || a.EvidenceManifestID == nil {
		t.Fatalf("no successful attachment: %+v %v", a, err)
	}
	later := prepare("pause")
	if later.ID <= *a.EvidenceManifestID {
		t.Fatal("fixture must be newer than published evidence")
	}
	r = campaignHTTPTestRequest(t, s, path, true)
	if r.Code != 200 {
		t.Fatalf("status %d %s", r.Code, r.Body)
	}
	if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Latest == nil || body.Latest.ID != *a.EvidenceManifestID || body.Latest.Authority != "candidate-only" {
		t.Fatalf("prepared row shadowed publication: %s", r.Body)
	}
	prepared, err := f.pg.NativeCampaignEvidenceList(context.Background(), f.task.ID, c.ID, 10, 0)
	if err != nil || len(prepared) != 3 {
		t.Fatalf("read deleted prepared evidence: %d %v", len(prepared), err)
	}
	published, err := f.pg.NativeCampaignPublishedEvidenceList(context.Background(), f.task.ID, c.ID, 10, 0)
	if err != nil || len(published) != 1 {
		t.Fatalf("published rows %d %v", len(published), err)
	}
}

func TestNativeCampaignHTTPRestoredNeverInspectsOrStarts(t *testing.T) {
	f := newT4AFixture(t, "http-restored-gate")
	c := f.createCampaign("restored")
	tx, err := f.pg.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SELECT id FROM tasks WHERE id=$1 FOR UPDATE`, f.task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO native_campaign_events(task_id,campaign_id,kind,payload) VALUES($1,$2,'campaign.archive_restored','{}')`, f.task.ID, c.ID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	s := &Server{jwtKey: []byte("campaign-http-test-key"), m: &Manager{pg: f.pg}, campaign: &nativeCampaignRuntime{service: f.service, manager: f.manager}}
	before := f.images.Calls()
	for _, action := range []string{"start", "resume"} {
		r := campaignHTTPPost(t, s, f.task.ID, fmt.Sprintf(`{"action":%q,"campaign_id":%d,"expected_state_version":%d,"request_id":%q}`, action, c.ID, c.StateVersion, "restored-"+action))
		if r.Code != 409 || !strings.Contains(r.Body.String(), "archive_restore_not_executable") {
			t.Fatalf("restored %s: %d %s", action, r.Code, r.Body)
		}
	}
	r := campaignHTTPPost(t, s, f.task.ID, fmt.Sprintf(`{"action":"validate","campaign_id":%d}`, c.ID))
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"can_start":false`) || !strings.Contains(r.Body.String(), "archive_restore_not_executable") {
		t.Fatalf("restored validate: %d %s", r.Code, r.Body)
	}
	if f.images.Calls() != before || f.factory.Count() != 0 {
		t.Fatal("restored record caused image/runner execution")
	}
}
