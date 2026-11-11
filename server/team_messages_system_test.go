package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestTeamSystemSessionShowsOnlyTaskLLMFailoverSummaries(t *testing.T) {
	f := newTeamContentFixture(t)
	store := f.task.Store
	rows := []db.Activity{
		{Worker: "system", Kind: "llm_switch", Summary: "模型额度不足，后续调用切换到备用模型", Detail: "TOOL_DETAIL_SECRET REASONING_SECRET", Metadata: json.RawMessage(`{"llm_transition":{"mode":"automatic","reason":"RAW_REASON_SECRET"}}`)},
		{Worker: "system", Kind: "llm_failover", Summary: "模型额度不足，配置链已耗尽", Detail: "RAW_ERROR_SECRET", Metadata: json.RawMessage(`{"llm_transition":{"mode":"exhausted","reason":"RAW_REASON_SECRET"}}`)},
		{Worker: "system", Kind: "llm_switch", Summary: "用户手动切换模型", Detail: "manual detail", Metadata: json.RawMessage(`{"llm_transition":{"mode":"manual"}}`)},
		{Worker: "mainagent", Kind: "llm_failover", Summary: "other session event", Detail: "other detail"},
		{Worker: "system", Kind: "text", Summary: "unrelated system activity", Detail: "unrelated detail"},
	}
	for _, row := range rows {
		if _, err := store.AppendActivity(row); err != nil {
			t.Fatal(err)
		}
	}

	host := httptest.NewTLSServer(f.s.TeamHandler())
	defer host.Close()
	request := func(path string, want int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, host.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.token)
		resp, err := host.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("GET %s status=%d want=%d body=%s", path, resp.StatusCode, want, body)
		}
		return body
	}
	base := fmt.Sprintf("/api/teams/%d/tasks/%s", f.team, f.task.ID)

	var sessionReply struct {
		Sessions []teamSession `json:"sessions"`
	}
	if err := json.Unmarshal(request(base+"/sessions", http.StatusOK), &sessionReply); err != nil {
		t.Fatal(err)
	}
	wantTitles := map[string]string{"plan": "规划 Planner · 态势研判", "system": "系统事件 · LLM 故障转移"}
	for id, title := range wantTitles {
		found := false
		for _, session := range sessionReply.Sessions {
			if session.ID == id {
				found = true
				if session.Title != title || session.CanMessage || session.State != "readonly" {
					t.Fatalf("session %q metadata mismatch: %+v", id, session)
				}
			}
		}
		if !found {
			t.Fatalf("session %q missing", id)
		}
	}

	path := base + "/messages?session=system"
	body := request(path, http.StatusOK)
	for _, expected := range []string{"模型额度不足，后续调用切换到备用模型", "模型额度不足，配置链已耗尽"} {
		if !bytes.Contains(body, []byte(expected)) {
			t.Fatalf("system summaries missing %q: %s", expected, body)
		}
	}
	if !bytes.Contains(body, []byte("用户手动切换模型")) {
		t.Fatalf("manual LLM switch summary missing: %s", body)
	}
	for _, forbidden := range []string{"TOOL_DETAIL_SECRET", "REASONING_SECRET", "RAW_REASON_SECRET", "RAW_ERROR_SECRET", "manual detail", "other session event", "unrelated system activity", "metadata", "detail"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("system session leaked %q: %s", forbidden, body)
		}
	}

	first := request(path+"&after=0&limit=1", http.StatusOK)
	var page struct {
		Items   []db.TeamMessage `json:"items"`
		HasMore bool             `json:"has_more"`
	}
	if err := json.Unmarshal(first, &page); err != nil || len(page.Items) != 1 || !page.HasMore {
		t.Fatalf("system since first page: %+v err=%v body=%s", page, err, first)
	}
	next := request(path+fmt.Sprintf("&after=%d&limit=1", page.Items[0].ID), http.StatusOK)
	if err := json.Unmarshal(next, &page); err != nil || len(page.Items) != 1 || page.Items[0].Text != "模型额度不足，配置链已耗尽" || !page.HasMore {
		t.Fatalf("system since next page: %+v err=%v body=%s", page, err, next)
	}
	last := request(path+fmt.Sprintf("&after=%d&limit=1", page.Items[0].ID), http.StatusOK)
	if err := json.Unmarshal(last, &page); err != nil || len(page.Items) != 1 || page.Items[0].Text != "用户手动切换模型" || page.HasMore {
		t.Fatalf("system since final page: %+v err=%v body=%s", page, err, last)
	}
}
