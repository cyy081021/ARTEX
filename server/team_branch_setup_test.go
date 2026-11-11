package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/artex/db"
)

type branchSetupFixture struct {
	s                                 *Server
	team, task, other, member, device int64
	token, base                       string
}

func newBranchSetupFixture(t *testing.T) *branchSetupFixture {
	t.Helper()
	s, task, other := workflowFixture(t)
	pg := s.m.pg
	ctx := context.Background()
	f := &branchSetupFixture{s: s, task: mustTaskID(t, task.ID), other: mustTaskID(t, other.ID)}
	team, err := pg.CreateTeam(ctx, "自动协作隔离验收")
	if err != nil {
		t.Fatal(err)
	}
	f.team = team.ID
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, f.team) })
	member, err := pg.CreateTeamMember(ctx, team.ID, "setup-member", "unused")
	if err != nil {
		t.Fatal(err)
	}
	f.member = member.ID
	if err = pg.SetTeamTaskPermissions(ctx, f.team, f.task, f.member, []string{"read", "execute", "manage"}); err != nil {
		t.Fatal(err)
	}
	if err = pg.SetPaused(f.task, true); err != nil {
		t.Fatal(err)
	}
	task.updateLifecycle(func(v *taskLifecycleState) { v.Paused = true })
	if _, err = pg.Exec(`INSERT INTO task_scope(task_id,kind,domain,source) VALUES($1,'root_domain','fixture.invalid','agent')`, f.task); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`INSERT INTO task_scope(task_id,kind,domain,source) VALUES($1,'root_domain','foreign.invalid','agent')`, f.other); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exploration(task.ExpID).AddConstraint("deny", "不得改变数据", "human"); err != nil {
		t.Fatal(err)
	}
	pair, err := pg.CreateTeamDevicePairing(ctx, f.team, f.member, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	caps := json.RawMessage(`{"version":1,"branch_protocol":1,"execution_enabled":true,"roles":["planner","worker","reviewer"],"role_capabilities":{"worker":["inspect"],"reviewer":["read_material"]},"branch_setup":{"version":1,"roles":{"planner":{"ready":true,"capabilities":[],"issues":[]},"worker":{"ready":true,"capabilities":["read_material","inspect"],"issues":[]},"reviewer":{"ready":true,"capabilities":["read_material"],"issues":[]}}}}`)
	device, _, err := pg.PairTeamDevice(ctx, pair, "浏览器执行设备", caps)
	if err != nil {
		t.Fatal(err)
	}
	f.device = device.ID
	if _, err = pg.Exec(`UPDATE team_devices SET last_seen_at=now() WHERE id=$1`, f.device); err != nil {
		t.Fatal(err)
	}
	f.token, err = signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	f.base = fmt.Sprintf("/api/teams/%d/tasks/%d/branches", f.team, f.task)
	return f
}

func (f *branchSetupFixture) call(t *testing.T, path string, body any, want int) []byte {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", f.base+path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+f.token)
	w := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s got %d want %d: %s", path, w.Code, want, w.Body.String())
	}
	return w.Body.Bytes()
}
func (f *branchSetupFixture) preview(t *testing.T) branchSetupPlan {
	t.Helper()
	var p branchSetupPlan
	raw := f.call(t, "/setup", branchSetupOptions{}, 200)
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBranchSetupPreviewAndConfirmation(t *testing.T) {
	f := newBranchSetupFixture(t)
	p := f.preview(t)
	if !p.CanEnable {
		t.Fatalf("not ready: %+v", p.Blockers)
	}
	if len(p.Assets) != 1 || p.Assets[0].Target != "fixture.invalid" {
		t.Fatalf("scope=%+v", p.Assets)
	}
	if len(p.Constraints) != 1 || len(p.Devices) != 1 || !p.Devices[0].Matched {
		t.Fatalf("plan=%+v", p)
	}
	if on, err := f.s.m.pg.BranchMode(context.Background(), f.task); err != nil || on {
		t.Fatalf("preview mutated mode: %v %v", on, err)
	}
	f.call(t, "/enable", map[string]any{"setup_token": p.Token, "setup_options": p.Options}, 400)
	f.call(t, "/enable", map[string]any{"setup_token": p.Token, "setup_options": p.Options, "confirm": true, "policy": map[string]any{"goal": "client override", "assets": []any{map[string]any{"id": "x", "target": "foreign.invalid"}}}}, 201)
	snap, err := f.s.m.pg.BranchSnapshot(context.Background(), f.team, f.task, collab.BranchActor{Admin: true}, 0, 0, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Project.State != "paused" || len(snap.Project.Pool) != 0 || len(snap.Project.Branches) != 0 {
		t.Fatalf("enable must not run: %+v", snap.Project)
	}
	var raw []byte
	if err = f.s.m.pg.QueryRow(`SELECT state FROM team_branch_projects WHERE task_id=$1`, f.task).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var stored collab.BranchProject
	if err = json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Policy.Goal == "client override" || len(stored.Policy.Assets) != 1 || len(stored.Policy.DeviceRoles) != 1 || !strings.Contains(stored.Policy.Roles["worker"].SystemPrompt, "不得改变数据") {
		t.Fatalf("invalid frozen policy: %+v", stored.Policy)
	}
	if !strings.Contains(string(raw), `"execute"`) {
		t.Fatal("matched member did not inherit execution permission")
	}
	f.call(t, "/enable", map[string]any{"setup_token": p.Token, "setup_options": p.Options, "confirm": true}, 409)
}

func TestBranchSetupStaleAndTamperedConfirmation(t *testing.T) {
	for _, change := range []string{"goal", "scope", "permission", "device", "options", "token", "actor", "expired"} {
		t.Run(change, func(t *testing.T) {
			f := newBranchSetupFixture(t)
			p := f.preview(t)
			if !p.CanEnable {
				t.Fatal(p.Blockers)
			}
			pg := f.s.m.pg
			var err error
			switch change {
			case "goal":
				_, err = pg.Exec(`UPDATE tasks SET goal='changed' WHERE id=$1`, f.task)
			case "scope":
				_, err = pg.Exec(`DELETE FROM task_scope WHERE task_id=$1`, f.task)
			case "permission":
				_, err = pg.Exec(`DELETE FROM team_task_permissions WHERE task_id=$1 AND member_id=$2 AND permission='execute'`, f.task, f.member)
			case "device":
				_, err = pg.Exec(`UPDATE team_devices SET capabilities=capabilities || '{"branch_setup":{}}'::jsonb WHERE id=$1`, f.device)
			case "options":
				p.Options.Budget++
			case "token":
				p.Token += "0"
			case "expired":
				p.Token = "1." + strings.Split(p.Token, ".")[1]
			case "actor":
				r := httptest.NewRequest("POST", f.base+"/setup", nil)
				plan, e := f.s.buildBranchSetup(r, f.team, f.task, p.Options)
				if e != nil {
					t.Fatal(e)
				}
				plan.ExpiresAt = p.ExpiresAt
				p.Token = f.s.branchSetupToken(plan, f.team, f.member, false)
			}
			if err != nil {
				t.Fatal(err)
			}
			f.call(t, "/enable", map[string]any{"setup_token": p.Token, "setup_options": p.Options, "confirm": true}, 409)
			if on, e := pg.BranchMode(context.Background(), f.task); e != nil || on {
				t.Fatalf("stale confirmation wrote project: %v %v", on, e)
			}
		})
	}
}

func TestBranchSetupOldNodeAndNoScopeBlocked(t *testing.T) {
	f := newBranchSetupFixture(t)
	if _, err := f.s.m.pg.Exec(`UPDATE team_devices SET capabilities=capabilities - 'branch_setup' WHERE id=$1`, f.device); err != nil {
		t.Fatal(err)
	}
	p := f.preview(t)
	if p.CanEnable || p.Devices[0].Matched {
		t.Fatalf("old node accepted: %+v", p)
	}
	if _, err := f.s.m.pg.Exec(`DELETE FROM task_scope WHERE task_id=$1`, f.task); err != nil {
		t.Fatal(err)
	}
	p = f.preview(t)
	if len(p.Assets) != 0 || p.CanEnable {
		t.Fatalf("goal expanded scope: %+v", p)
	}
}

func TestBranchSetupTransactionRejectsChangedSource(t *testing.T) {
	f := newBranchSetupFixture(t)
	r := httptest.NewRequest("POST", f.base+"/setup", nil)
	p, err := f.s.buildBranchSetup(r, f.team, f.task, branchSetupOptions{})
	if err != nil || !p.CanEnable {
		t.Fatalf("plan=%+v err=%v", p, err)
	}
	if _, err = f.s.m.pg.Exec(`UPDATE tasks SET goal='changed after validation' WHERE id=$1`, f.task); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.m.pg.CreateBranchProject(context.Background(), f.team, f.task, collab.BranchActor{Admin: true}, p.policy, p.sourceDigest); err == nil {
		t.Fatal("transaction accepted stale source")
	}
}

func TestBranchSetupAutomaticDispatchThroughDatabase(t *testing.T) {
	f := newBranchSetupFixture(t)
	pg := f.s.m.pg
	ctx := context.Background()
	first, err := pg.GetTeamDevice(ctx, f.team, f.device)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := pg.CreateTeamDevicePairing(ctx, f.team, f.member, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := pg.PairTeamDevice(ctx, pair, "另一个工具设备", json.RawMessage(strings.ReplaceAll(string(first.Capabilities), "inspect", "inspect_other")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`UPDATE team_devices SET last_seen_at=now() WHERE id=$1`, second.ID); err != nil {
		t.Fatal(err)
	}
	p := f.preview(t)
	if !p.CanEnable {
		t.Fatal(p.Blockers)
	}
	f.call(t, "/enable", map[string]any{"setup_token": p.Token, "setup_options": p.Options, "confirm": true}, 201)
	for i, cap := range []string{"inspect", "inspect_other"} {
		work := collab.BranchWorkSpec{Title: fmt.Sprintf("bounded-%d", i), Question: "inspect fixture", Kind: "pentest", Roles: []string{"worker", "reviewer"}, Budget: 10, RequiredCapabilities: map[string][]string{"worker": {cap}}}
		_, err = pg.ApplyBranchCommand(ctx, f.team, f.task, collab.BranchActor{Admin: true}, collab.BranchCommand{Type: "publish", RequestID: fmt.Sprintf("publish-%d", i), Work: &work})
		if err != nil {
			t.Fatal(err)
		}
	}
	snap, err := pg.BranchSnapshot(ctx, f.team, f.task, collab.BranchActor{Admin: true}, 0, 0, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Project.Branches) != 0 {
		t.Fatal("paused project auto started")
	}
	_, err = pg.ApplyBranchCommand(ctx, f.team, f.task, collab.BranchActor{Admin: true}, collab.BranchCommand{Type: "project_resume", RequestID: "start-automatic", Revision: snap.Project.Revision})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			dev := first
			if i%2 == 1 {
				dev = second
			}
			_, e := pg.BranchDevicePoll(ctx, dev)
			failures <- e
		}(i)
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		if e != nil {
			t.Fatal(e)
		}
	}
	snap, err = pg.BranchSnapshot(ctx, f.team, f.task, collab.BranchActor{Admin: true}, 0, 0, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Project.Branches) != 3 {
		t.Fatalf("expected 2 workers + one coordinator, got %+v", snap.Project.Branches)
	}
	for _, dev := range []*db.TeamDevice{first, second} {
		replies, e := pg.BranchDevicePoll(ctx, dev)
		if e != nil {
			t.Fatal(e)
		}
		for _, reply := range replies {
			cap := "inspect"
			foreign := "inspect_other"
			if dev.ID == second.ID {
				cap, foreign = foreign, cap
			}
			caps := reply.Policy.Roles["worker"].Capabilities
			if !strings.Contains(strings.Join(caps, ","), cap) {
				t.Fatalf("own tools missing: %+v", caps)
			}
			for _, c := range caps {
				if c == foreign {
					t.Fatal("peer tools leaked into own executable role")
				}
			}
		}
	}
}
