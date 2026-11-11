package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
)

func TestTeamTaskDetailReadScopeProjectionAndRevocation(t *testing.T) {
	s, task, other := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	tid := mustTaskID(t, task.ID)
	team, err := pg.CreateTeam(ctx, "task detail fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	member, err := pg.CreateTeamMember(ctx, team.ID, "reader", "unused")
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.AttachTeamTask(ctx, team.ID, tid, member.ID, "read"); err != nil {
		t.Fatal(err)
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: fmt.Sprintf("team:%d:%d", team.ID, member.ID), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}).SignedString(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	host := httptest.NewTLSServer(s.TeamHandler())
	defer host.Close()
	get := func(path string, code int) []byte {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, host.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, e := host.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		var b bytes.Buffer
		_, _ = b.ReadFrom(resp.Body)
		if resp.StatusCode != code {
			t.Fatalf("GET %s: status=%d want=%d body=%s", path, resp.StatusCode, code, b.String())
		}
		return b.Bytes()
	}
	base := fmt.Sprintf("/api/teams/%d/tasks/%d", team.ID, tid)
	{
		raw := get(base, 200)
		var response struct {
			Task struct {
				ID          int64   `json:"id"`
				Name        string  `json:"name"`
				Kind        string  `json:"kind"`
				Goal        string  `json:"goal"`
				Status      string  `json:"status"`
				Paused      bool    `json:"paused"`
				Queued      bool    `json:"queued"`
				CreatedAt   string  `json:"created_at"`
				CompletedAt *string `json:"completed_at"`
			} `json:"task"`
			Permissions map[string]bool `json:"permissions"`
			IsAdmin     bool            `json:"is_admin"`
			MemberID    int64           `json:"member_id"`
		}
		if err = json.Unmarshal(raw, &response); err != nil {
			t.Fatalf("detail JSON %s: %v", raw, err)
		}
		if response.Task.ID != tid || response.Task.Kind != "pentest" || response.Task.Goal != "check frame" || response.Task.CreatedAt == "" {
			t.Fatalf("incomplete task projection: %+v", response.Task)
		}
		if response.Permissions["read"] != true || response.Permissions["execute"] || response.Permissions["manage"] || response.Permissions["review"] || response.IsAdmin || response.MemberID != member.ID {
			t.Fatalf("unexpected read-only authorization: %+v", response)
		}
		var object map[string]json.RawMessage
		if err = json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		allowedTop := map[string]bool{"task": true, "permissions": true, "is_admin": true, "member_id": true}
		for key := range object {
			if !allowedTop[key] {
				t.Errorf("unexpected top-level field %q", key)
			}
		}
		var taskObject map[string]json.RawMessage
		if err = json.Unmarshal(object["task"], &taskObject); err != nil {
			t.Fatal(err)
		}
		allowedTask := map[string]bool{"id": true, "name": true, "kind": true, "goal": true, "status": true, "paused": true, "queued": true, "created_at": true, "completed_at": true}
		for key := range taskObject {
			if !allowedTask[key] {
				t.Errorf("unexpected task projection field %q", key)
			}
		}
		var permissionObject map[string]json.RawMessage
		if err = json.Unmarshal(object["permissions"], &permissionObject); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"read", "execute", "manage", "review"} {
			if _, ok := permissionObject[key]; !ok {
				t.Errorf("permission key %q missing", key)
			}
		}
		if len(permissionObject) != 4 {
			t.Errorf("unexpected permission projection: %v", permissionObject)
		}
	}
	get(fmt.Sprintf("/api/teams/%d/tasks/%s", team.ID, other.ID), 403)
	otherTeam, err := pg.CreateTeam(ctx, "unshared task detail fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, otherTeam.ID) })
	get(fmt.Sprintf("/api/teams/%d/tasks/%d", otherTeam.ID, tid), 403)
	if _, err = pg.Exec(`DELETE FROM team_task_permissions WHERE team_id=$1 AND member_id=$2 AND permission='read'`, team.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	get(base, 403)
}

func TestTeamRunningWorkerRemainsMessageEligible(t *testing.T) {
	s, task, _ := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	tid := mustTaskID(t, task.ID)
	team, err := pg.CreateTeam(ctx, "running worker session fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM team_execution_assignments WHERE team_id=$1`, team.ID)
		_, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID)
	})
	member, err := pg.CreateTeamMember(ctx, team.ID, "executor", "unused")
	if err != nil {
		t.Fatal(err)
	}
	for _, permission := range []string{"read", "execute"} {
		if err = pg.AttachTeamTask(ctx, team.ID, tid, member.ID, permission); err != nil {
			t.Fatal(err)
		}
	}
	pair, err := pg.CreateTeamDevicePairing(ctx, team.ID, member.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	device, deviceToken, err := pg.PairTeamDevice(ctx, pair, "worker", json.RawMessage(`{"version":1,"message_protocol":1,"execution_enabled":true,"roles":["worker"],"capabilities":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	iid, err := task.Store.AddWorkIntent(ctx, "running worker", 1, nil, nil, db.WorkContract{})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := pg.GetTask(tid)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.prepareTeamAssignment(ctx, team.ID, stored, teamAssignInput{IntentID: iid, DeviceID: device.ID}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pg.ClaimTeamExecutionAssignment(ctx, a.ID, device.ID, deviceToken, a.Epoch); err != nil {
		t.Fatal(err)
	}
	assertWorkerEligibility := func(want bool) {
		t.Helper()
		items, e := s.sharedSessions(ctx, stored, team.ID, true)
		if e != nil {
			t.Fatal(e)
		}
		for _, item := range items {
			if item.ID == fmt.Sprintf("intent:%d", iid) {
				if item.CanMessage != want {
					t.Fatalf("worker eligibility=%v want=%v: %+v", item.CanMessage, want, item)
				}
				if !want && item.Reason == "" {
					t.Fatalf("ineligible worker has no reason: %+v", item)
				}
				return
			}
		}
		t.Fatalf("worker session intent:%d missing from %+v", iid, items)
	}
	assertWorkerEligibility(false) // a remote claim is not message-ready until its first exchange
	if _, err = pg.ExchangeTeamMessages(ctx, a.ID, device.ID, deviceToken, collab.MessageExchange{Epoch: a.Epoch}); err != nil {
		t.Fatal(err)
	}
	assertWorkerEligibility(true)

	// A local Work with a live control remains steerable when task-level status
	// is running. This guards against deriving message eligibility from that
	// status alone.
	localID, err := task.Store.AddWorkIntent(ctx, "local running worker", 1, nil, nil, db.WorkContract{})
	if err != nil {
		t.Fatal(err)
	}
	if err = task.Store.SetNodeState(localID, "running"); err != nil {
		t.Fatal(err)
	}
	if err = s.m.SetTaskStatus(task.ID, "running"); err != nil {
		t.Fatal(err)
	}
	localCtx, cancel := context.WithCancelCause(ctx)
	control := agent.NewLiveControl(cancel)
	s.engine.workMu.Lock()
	s.engine.work[localID] = &workExecution{control: control}
	s.engine.workMu.Unlock()
	t.Cleanup(func() {
		s.engine.workMu.Lock()
		delete(s.engine.work, localID)
		s.engine.workMu.Unlock()
		control.Close()
		cancel(nil)
		_ = localCtx
	})
	stored, err = pg.GetTask(tid)
	if err != nil {
		t.Fatal(err)
	}
	items, err := s.sharedSessions(ctx, stored, team.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.ID == fmt.Sprintf("intent:%d", localID) {
			if !item.CanMessage {
				t.Fatalf("running local worker with live control unexpectedly cannot receive messages: %+v", item)
			}
			break
		}
	}
	foundLocal := false
	for _, item := range items {
		if item.ID == fmt.Sprintf("intent:%d", localID) && item.CanMessage {
			foundLocal = true
		}
	}
	if !foundLocal {
		t.Fatalf("local worker session intent:%d missing or ineligible from %+v", localID, items)
	}
}

func TestTeamSharedSessionsHaveActionableReasons(t *testing.T) {
	s, task, _ := workflowFixture(t)
	ctx := context.Background()
	team, err := s.m.pg.CreateTeam(ctx, "session reasons fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	member, err := s.m.pg.CreateTeamMember(ctx, team.ID, "reader", "unused")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.m.pg.AttachTeamTask(ctx, team.ID, mustTaskID(t, task.ID), member.ID, "read"); err != nil {
		t.Fatal(err)
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: fmt.Sprintf("team:%d:%d", team.ID, member.ID), ExpiresAt: jwt.NewNumericDate(jwt.NewNumericDate(time.Now().Add(time.Hour)).Time)}).SignedString(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/teams/%d/tasks/%d/sessions", team.ID, mustTaskID(t, task.ID)), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("sessions status=%d: %s", w.Code, w.Body.String())
	}
	var payload struct {
		Sessions []struct {
			ID         string `json:"id"`
			CanMessage bool   `json:"can_message"`
			Reason     string `json:"reason"`
		} `json:"sessions"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, v := range payload.Sessions {
		if v.ID == "main:0" || v.ID == "plan" {
			seen[v.ID] = true
			if v.CanMessage || v.Reason == "" {
				t.Errorf("%s must be read-only with a reason: %+v", v.ID, v)
			}
			lower := strings.ToLower(v.Reason)
			if v.ID == "main:0" && !strings.Contains(lower, "只读") && !strings.Contains(lower, "主") {
				t.Errorf("main reason lacks shared read-only guidance: %q", v.Reason)
			}
			if v.ID == "plan" && !strings.Contains(lower, "规划") && !strings.Contains(lower, "自动") {
				t.Errorf("plan reason lacks planner context: %q", v.Reason)
			}
		}
	}
	if !seen["main:0"] || !seen["plan"] {
		t.Fatalf("expected main and plan sessions: %+v", payload.Sessions)
	}
	// Main's state tracks the active chat segment, never task-level running.
	currentSeg, err := task.Store.CurrentMainSeg()
	if err != nil {
		t.Fatal(err)
	}
	readSession := func(wantState string) []teamSession {
		t.Helper()
		stored, e := s.m.pg.GetTask(mustTaskID(t, task.ID))
		if e != nil {
			t.Fatal(e)
		}
		items, e := s.sharedSessions(ctx, stored, team.ID, true)
		if e != nil {
			t.Fatal(e)
		}
		for _, item := range items {
			if item.ID == fmt.Sprintf("main:%d", currentSeg) {
				if item.State != wantState {
					t.Fatalf("main state=%q want=%q: %+v", item.State, wantState, item)
				}
				return items
			}
		}
		t.Fatalf("main segment %d missing: %+v", currentSeg, items)
		return nil
	}
	readSession("idle")
	mainControl := agent.NewLiveControl(nil)
	s.chatLive.Store(task.ID, chatLiveRun{control: mainControl, seg: currentSeg})
	t.Cleanup(func() { s.chatLive.Delete(task.ID); mainControl.Close() })
	readSession("running")
	misaligned := agent.NewLiveControl(nil)
	s.chatLive.Store(task.ID, chatLiveRun{control: misaligned, seg: currentSeg + 1})
	readSession("idle")
	s.chatLive.Delete(task.ID)
	misaligned.Close()

	workerID, err := task.Store.AddWorkIntent(ctx, "reason worker", 1, nil, nil, db.WorkContract{})
	if err != nil {
		t.Fatal(err)
	}
	assertReason := func(taskSnapshot *db.Task, steer bool, want string) {
		t.Helper()
		items, e := s.sharedSessions(ctx, taskSnapshot, team.ID, steer)
		if e != nil {
			t.Fatal(e)
		}
		for _, item := range items {
			if item.ID == fmt.Sprintf("intent:%d", workerID) {
				if item.CanMessage || item.Reason == "" || !strings.Contains(item.Reason, want) {
					t.Fatalf("worker reason lacks %q: %+v", want, item)
				}
				return
			}
		}
		t.Fatalf("worker %d missing from sessions", workerID)
	}
	stored, err := s.m.pg.GetTask(mustTaskID(t, task.ID))
	if err != nil {
		t.Fatal(err)
	}
	assertReason(stored, false, "权限")
	assertReason(stored, true, "尚未开始") // open Work waits for execution
	if err = task.Store.SetNodeState(workerID, "running"); err != nil {
		t.Fatal(err)
	}
	assertReason(stored, true, "通道") // running remote Work without a live control/channel
	if err = task.Store.SetNodeState(workerID, "done"); err != nil {
		t.Fatal(err)
	}
	assertReason(stored, true, "结束")
	if err = s.m.SetTaskPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	stored, err = s.m.pg.GetTask(mustTaskID(t, task.ID))
	if err != nil {
		t.Fatal(err)
	}
	assertReason(stored, true, "暂停")
	if err = s.m.SetTaskPaused(task.ID, false); err != nil {
		t.Fatal(err)
	}
	if err = s.m.SetTaskStatus(task.ID, "done"); err != nil {
		t.Fatal(err)
	}
	stored, err = s.m.pg.GetTask(mustTaskID(t, task.ID))
	if err != nil {
		t.Fatal(err)
	}
	assertReason(stored, true, "结束")
}

func TestTeamTaskMemberHTMLExactPaths(t *testing.T) {
	h := sTeamOnlySentinel()
	for _, path := range []string{"/function/team/task", "/function/team/task/"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Errorf("GET %s: status=%d want=%d", path, w.Code, http.StatusNoContent)
		}
	}
	for _, path := range []string{"/function/team/settings", "/function/team/admin"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s: status=%d want=%d", path, w.Code, http.StatusNotFound)
		}
	}
}

func sTeamOnlySentinel() http.Handler {
	return (&Server{}).teamOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
}
