package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExplicitWebScenarioWaitsForMaterials(t *testing.T) {
	m, s := newAutoRouteAPITestServer(t)
	s.llmProv = &routeFixtureProvider{text: `{"primary_kind":"pentest","capabilities":["web"],"reason":"synthetic classification fixture","needs_materials":["readme.txt"]}`}
	request := httptest.NewRequest("POST", "/api/tasks", strings.NewReader(`{"scenario":"web","description":"metadata fixture","goal":"check routing metadata","material_hints":[{"name":"readme.txt","size":7}]}`))
	result := httptest.NewRecorder()
	s.createTask(result, request)
	if result.Code != 201 {
		t.Fatalf("create returned %d: %s", result.Code, result.Body.String())
	}
	var body struct {
		Task TaskDTO `json:"task"`
	}
	if err := json.Unmarshal(result.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Task.ID == "" {
		t.Fatal("missing task id")
	}
	t.Cleanup(func() {
		if _, err := m.DeleteTask(body.Task.ID, DeleteTaskOptions{}); err != nil {
			t.Error(err)
		}
	})
	if body.Task.Scenario != "web" || body.Task.Kind != "pentest" || !body.Task.Paused {
		t.Fatalf("unexpected task identity or material state: %#v", body.Task)
	}
}
