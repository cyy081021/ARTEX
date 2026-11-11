package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/collab"
)

// This opt-in acceptance test runs the compiled Node against a local fake
// provider and the real server/database state machine. It never contacts an
// external model or target.
func TestBranchAutoNodeDispatchReviewEndToEnd(t *testing.T) {
	binary := os.Getenv("ARTEX_NODE_ACCEPTANCE_BINARY")
	if binary == "" {
		t.Skip("ARTEX_NODE_ACCEPTANCE_BINARY is unset")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("acceptance binary: %v", err)
	}
	s, _, task := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	tid := mustTaskID(t, task.ID)
	if _, err := pg.Exec(`UPDATE tasks SET paused=true,status='created',queued=false WHERE id=$1`, tid); err != nil {
		t.Fatal(err)
	}
	team, err := pg.CreateTeam(ctx, "automatic node acceptance")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	member, err := pg.CreateTeamMember(ctx, team.ID, "automatic operator", "unused")
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.SetTeamTaskPermissions(ctx, team.ID, tid, member.ID, []string{"read", "execute", "manage"}); err != nil {
		t.Fatal(err)
	}
	if err = pg.SetPaused(tid, true); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`INSERT INTO task_scope(task_id,kind,domain,source) VALUES($1,'root_domain','fixture.invalid','agent')`, tid); err != nil {
		t.Fatal(err)
	}
	pair, err := pg.CreateTeamDevicePairing(ctx, team.ID, member.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	capReport := `"branch_setup":{"version":1,"roles":{"reverse_planner":{"ready":true,"capabilities":[],"issues":[]},"reverse_static":{"ready":true,"capabilities":["read_material"],"issues":[]},"reverse_reviewer":{"ready":true,"capabilities":["read_material"],"issues":[]}}}`
	caps := json.RawMessage(`{"version":1,"branch_protocol":1,"execution_enabled":true,"roles":["reverse_planner","reverse_static","reverse_reviewer"],"role_capabilities":{"reverse_static":["read_material"],"reverse_reviewer":["read_material"]},` + capReport + `}`)
	device, token, err := pg.PairTeamDevice(ctx, pair, "local acceptance node", caps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`UPDATE team_devices SET last_seen_at=now() WHERE id=$1`, device.ID); err != nil {
		t.Fatal(err)
	}
	material := []byte("owned automatic-branch fixture: exact source evidence\n")
	hash := collab.ContentHash(material)
	prefix := s.teamMaterialPrefix(team.ID, tid)
	if err = os.MkdirAll(filepath.Join(s.m.dir, prefix), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(s.m.dir, prefix, hash), material, 0600); err != nil {
		t.Fatal(err)
	}
	admin := collab.BranchActor{Admin: true}
	policy := collab.BranchPolicy{
		Version: 1, Goal: "inspect the authorized fixture and independently verify the result", Budget: 80,
		MaxToolSeconds: 30, Kinds: []string{"reverse"}, AutoPublish: true, AutoDispatch: true, AutoReview: true,
		Assets:         []collab.BranchAsset{{ID: "scope-fixture", Target: "fixture.invalid", Version: collab.ContentHash([]byte("fixture.invalid"))}},
		Materials:      []collab.Material{{ID: hash, SHA256: hash, Size: int64(len(material)), Name: "owned-fixture.txt"}},
		PlannerPrompts: map[string]string{"reverse": "coordinator fixture"}, Constraints: []string{"keep the supplied fixture unchanged"}, Roles: map[string]collab.ExecutionConfig{},
		DeviceRoles: map[string]map[string][]string{fmt.Sprint(device.ID): {"reverse_planner": {}, "reverse_static": {"read_material"}, "reverse_reviewer": {"read_material"}}},
	}
	for _, role := range []string{"reverse_static", "reverse_reviewer"} {
		caps := []string{}
		if role == "reverse_static" || role == "reverse_reviewer" {
			caps = []string{"read_material"}
		}
		policy.Roles[role] = collab.ExecutionConfig{Version: 1, Kind: "reverse", Role: role, SystemPrompt: "role fixture", MaxTurns: 5, BudgetSeconds: 30, Capabilities: caps}
	}
	_, err = pg.CreateBranchProject(ctx, team.ID, tid, admin, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, permission := range collab.BranchPermissions {
		if _, err = pg.ApplyBranchCommand(ctx, team.ID, tid, admin, collab.BranchCommand{Type: "grant", RequestID: "grant-" + permission, MemberID: member.ID, Permission: permission}); err != nil {
			t.Fatal(err)
		}
	}
	beforeResume, err := pg.BranchSnapshot(ctx, team.ID, tid, admin, 0, 0, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = pg.ApplyBranchCommand(ctx, team.ID, tid, admin, collab.BranchCommand{Type: "project_resume", RequestID: "automatic-resume", Revision: beforeResume.Project.Revision})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := pg.BranchSnapshot(ctx, team.ID, tid, admin, 0, 0, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(initial.Project.Branches) != 1 || !initial.Project.Branches[0].Spec.Coordinator || initial.Project.Branches[0].DeviceID != device.ID {
		t.Fatalf("resume did not auto-create and claim coordinator root: %+v", initial.Project)
	}

	var mu sync.Mutex
	coordinatorCalls, childPlannerCalls, workerCalls, reviewerCalls := 0, 0, 0, 0
	coordinatorSawPolicy, workerReadFixture, reviewHadExactVersion := false, false, false
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(raw, &req)
		if r.Header.Get("Authorization") != "Bearer isolated-auto-model-key" {
			t.Errorf("unexpected fake provider authorization")
		}
		mu.Lock()
		defer mu.Unlock()
		name, content := "", ""
		var args any
		switch req.Model {
		case "auto-planner":
			if bytes.Contains(raw, []byte(`"coordinator":true`)) || bytes.Contains(raw, []byte(`\"coordinator\":true`)) {
				coordinatorCalls++
				coordinatorSawPolicy = coordinatorSawPolicy || bytes.Contains(raw, []byte("constraints"))
				if coordinatorCalls == 1 {
					name = "publish_branch"
					args = map[string]any{"work": collab.BranchWorkSpec{Title: "fixture static check", Question: "inspect only the approved local material and provide exact evidence", Kind: "reverse", Roles: []string{"reverse_static"}, AssetIDs: []string{"scope-fixture"}, MaterialHashes: []string{hash}, RequiredCapabilities: map[string][]string{"reverse_static": {"read_material"}}, Acceptance: []string{"cite the fixture bytes"}, Budget: 30}}
				} else {
					name = "branch_wait"
					args = map[string]any{"reason": "wait for the dispatched branch result"}
					// No original single-branch planner instruction should leak into
					// the dedicated coordination session.
					var envelope struct {
						Messages []struct {
							Role    string `json:"role"`
							Content string `json:"content"`
						} `json:"messages"`
					}
					_ = json.Unmarshal(raw, &envelope)
					system := ""
					for _, message := range envelope.Messages {
						if message.Role == "system" {
							system += message.Content
						}
					}
					if !strings.Contains(system, "isolated coordinator") || strings.Contains(system, "persistent planner for this branch") {
						t.Errorf("unexpected coordinator prompt: %q", system)
					}
				}
			} else {
				childPlannerCalls++
				if childPlannerCalls <= 2 {
					role, key := "reverse_static", "inspect-fixture"
					var deps []int64
					if childPlannerCalls == 2 {
						role, key = "reverse_reviewer", "independent-review"
						deps = []int64{1}
					}
					contract, _ := json.Marshal(map[string]any{"execution_role": role, "hypothesis": "the authorized fixture is unchanged", "acceptance": []string{"cite exact fixture bytes"}, "budget_seconds": 20, "depends_on": deps})
					name = "propose_work"
					args = map[string]any{"unit": collab.BranchUnitSpec{Key: key, Question: "read the approved fixture and report evidence", Role: role, MaterialHashes: []string{hash}, Contract: contract, DependsOn: deps}}
				} else {
					name = "submit_branch"
					args = map[string]any{"outcome": "candidate", "text": "worker result and independent review are ready"}
				}
			}
		case "auto-worker":
			workerCalls++
			if workerCalls == 1 || !bytes.Contains(raw, []byte("owned automatic-branch fixture")) {
				name = "read_material"
				args = map[string]any{"sha256": hash}
			} else {
				workerReadFixture = true
				content = `{"outcome":"candidate","summary":"The exact owned fixture bytes were read and cited."}`
			}
		case "auto-reviewer":
			reviewerCalls++
			versionRE := regexp.MustCompile(`evidence_version.{0,16}([a-f0-9]{64})`)
			match := versionRE.FindSubmatch(raw)
			if len(match) == 2 {
				reviewHadExactVersion = true
				unitID := "1"
				if idMatch := regexp.MustCompile(`unit_id.{0,16}([0-9]+)`).FindSubmatch(raw); len(idMatch) == 2 {
					unitID = string(idMatch[1])
				}
				content = fmt.Sprintf(`{"outcome":"candidate","summary":"Independent reviewer checked the result against the fixture and acceptance criterion.","review":{"decision":"accept","reason":"The result cites the exact authorized fixture and meets the stated criterion.","acceptance_met":true,"evidence_versions":{"%s":"%s"},"uncertainties":[]}}`, unitID, match[1])
			} else {
				content = `{"outcome":"candidate","summary":"Review response generated.","review":{"decision":"needs_human","reason":"Evidence version unavailable.","acceptance_met":false,"evidence_versions":{},"uncertainties":["missing evidence version"]}}`
			}
		default:
			t.Errorf("unexpected fake model %q", req.Model)
			content = `{"outcome":"failed","summary":"unexpected model"}`
		}
		w.Header().Set("Content-Type", "text/event-stream")
		if name != "" {
			argument, _ := json.Marshal(args)
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"auto-fixture-call\",\"type\":\"function\",\"function\":{\"name\":%q,\"arguments\":%q}}]}}]}\n\n", name, string(argument))
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n")
		} else {
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q},\"finish_reason\":\"stop\"}]}\n\n", content)
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer model.Close()
	host := httptest.NewTLSServer(s.TeamHandler())
	defer host.Close()
	cert, err := x509.ParseCertificate(host.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	ca := filepath.Join(temp, "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	roles, models := map[string]any{}, map[string]any{}
	for _, bind := range []struct{ role, model string }{{"reverse_planner", "auto-planner"}, {"reverse_static", "auto-worker"}, {"reverse_reviewer", "auto-reviewer"}} {
		roles[bind.role] = map[string]any{"model": bind.model}
		models[bind.model] = map[string]any{"endpoint": model.URL, "api_key_env": "ARTEX_BRANCH_FAKE_KEY", "model": bind.model, "format": "openai"}
	}
	cfg := map[string]any{"coordinator_url": host.URL, "ca_file": ca, "server_name": "127.0.0.1", "execution": map[string]any{"work_dir": filepath.Join(temp, "work"), "outbox_dir": filepath.Join(temp, "outbox"), "branches": map[string]any{"enabled": true, "material_mode": "assigned"}, "roles": roles, "models": models, "commands": map[string]any{}}}
	cfgPath := filepath.Join(temp, "node.json")
	raw, _ := json.Marshal(cfg)
	if err = os.WriteFile(cfgPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(temp, "identity.json")
	raw, _ = json.Marshal(map[string]any{"coordinator_url": host.URL, "device_token": token, "device": map[string]any{"id": device.ID, "name": device.Name}})
	if err = os.WriteFile(state, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var snap *collab.BranchSnapshot
	for round := 0; round < 14; round++ {
		runCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
		cmd := exec.CommandContext(runCtx, binary, "-config", cfgPath, "-state", state, "run-once")
		cmd.Env = append(os.Environ(), "ARTEX_BRANCH_FAKE_KEY=isolated-auto-model-key")
		out, runErr := cmd.CombinedOutput()
		cancel()
		if runErr != nil {
			t.Fatalf("real Node round %d: %v\n%s", round, runErr, out)
		}
		snapshot, e := pg.BranchSnapshot(ctx, team.ID, tid, admin, 0, 0, 250, "")
		if e != nil {
			t.Fatal(e)
		}
		if snapshot.Project.State != "running" {
			t.Fatalf("main project unexpectedly completed: %s", snapshot.Project.State)
		}
		var childAccepted bool
		for _, branch := range snapshot.Project.Branches {
			if !branch.Spec.Coordinator && branch.State == "accepted" {
				childAccepted = true
			}
		}
		if childAccepted {
			snap = snapshot
			break
		}
	}
	if snap == nil {
		snapshot, e := pg.BranchSnapshot(ctx, team.ID, tid, admin, 0, 0, 250, "")
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(snapshot.Project)
		t.Fatalf("automatic flow did not reach acceptance: %s", raw)
	}
	var child *collab.ExecutionBranch
	for i := range snap.Project.Branches {
		if !snap.Project.Branches[i].Spec.Coordinator {
			child = &snap.Project.Branches[i]
		}
	}
	if child == nil || child.State != "accepted" || child.ReviewMode != "automatic" || child.ReviewReason == "" || child.Units == nil || len(child.Units) != 2 {
		raw, _ := json.Marshal(snap.Project)
		t.Fatalf("automatic acceptance record incomplete: %s", raw)
	}
	if child.Units[0].EvidenceVersion == "" || child.Units[1].Spec.Role != "reverse_reviewer" || child.Units[1].Result == nil || child.Units[1].Result.Review == nil || child.Units[1].Result.Review.Decision != "accept" {
		t.Fatalf("review evidence was not attached: %+v", child.Units)
	}
	mu.Lock()
	cc, pc, wc, rc, sawPolicy, readMaterial, exactVersion := coordinatorCalls, childPlannerCalls, workerCalls, reviewerCalls, coordinatorSawPolicy, workerReadFixture, reviewHadExactVersion
	mu.Unlock()
	if cc < 1 || pc < 3 || wc < 2 || rc < 1 || !sawPolicy || !readMaterial || !exactVersion {
		t.Fatalf("fake model evidence incomplete coordinator=%d planner=%d worker=%d reviewer=%d policy=%v read=%v version=%v", cc, pc, wc, rc, sawPolicy, readMaterial, exactVersion)
	}
	// Let the coordinator consume the new accepted result once, then exercise
	// unchanged heartbeats. The stable journal snapshot must suppress model work.
	for i := 0; i < 4; i++ {
		runCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
		cmd := exec.CommandContext(runCtx, binary, "-config", cfgPath, "-state", state, "run-once")
		cmd.Env = append(os.Environ(), "ARTEX_BRANCH_FAKE_KEY=isolated-auto-model-key")
		out, runErr := cmd.CombinedOutput()
		cancel()
		if runErr != nil {
			t.Fatalf("stable-poll Node round %d: %v\n%s", i, runErr, out)
		}
	}
	mu.Lock()
	cc2 := coordinatorCalls
	mu.Unlock()
	if cc2 > cc+1 {
		t.Fatalf("unchanged coordinator state caused repeated model requests: before=%d after=%d", cc, cc2)
	}
	if strings.Contains(fmt.Sprint(snap.Events), "isolated-auto-model-key") {
		t.Fatal("fake model credential entered shared events")
	}
	t.Logf("real automatic flow accepted: coordinator=%d worker=%d reviewer=%d, evidence_version=%s, project=%s, polls=4", cc2, wc, rc, child.Units[0].EvidenceVersion, snap.Project.State)
}
