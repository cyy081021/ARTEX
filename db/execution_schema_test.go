package db

import (
	"encoding/json"
	"testing"
)

func TestExecutionToolSchemaUpgradePreservesSettings(t *testing.T) {
	d, _, _ := executionFixture(t)
	key := "execution-schema-fixture"
	_, _ = d.Exec(`DELETE FROM tools WHERE key=$1`, key)
	defer d.Exec(`DELETE FROM tools WHERE key=$1`, key)
	if err := d.SeedTool(key, "operator text", json.RawMessage(`{"type":"object","properties":{"reason":{"type":"string","description":"operator note","default":"keep"}},"required":["reason"]}`), json.RawMessage(`["planner"]`)); err != nil {
		t.Fatal(err)
	}
	_, _ = d.Exec(`UPDATE tools SET enabled=false WHERE key=$1`, key)
	for i := 0; i < 2; i++ {
		if err := d.EnsureToolSchemaFields(key, map[string]any{"goal_version": map[string]any{"type": "string"}}, []string{"reason", "goal_version"}); err != nil {
			t.Fatal(err)
		}
	}
	row, err := d.GetTool(key)
	if err != nil {
		t.Fatal(err)
	}
	if row.Enabled || row.Description != "operator text" || len(row.Agents) != 1 || row.Agents[0] != "planner" {
		t.Fatalf("settings overwritten %+v", row)
	}
	var schema struct {
		Properties map[string]map[string]any `json:"properties"`
		Required   []string                  `json:"required"`
	}
	if err = json.Unmarshal(row.Schema, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.Properties["reason"]["default"] != "keep" || schema.Properties["reason"]["description"] != "operator note" || schema.Properties["goal_version"]["type"] != "string" || len(schema.Required) != 2 {
		t.Fatal(string(row.Schema))
	}
}

func TestEnsureToolAgentsRepairsOnlyEmptyBindings(t *testing.T) {
	d, _, _ := executionFixture(t)
	for _, key := range []string{"agents-empty-fixture", "agents-bound-fixture"} {
		_, _ = d.Exec(`DELETE FROM tools WHERE key=$1`, key)
		defer d.Exec(`DELETE FROM tools WHERE key=$1`, key)
	}
	if err := d.SeedTool("agents-empty-fixture", "empty", nil, json.RawMessage(`[]`)); err != nil {
		t.Fatal(err)
	}
	if err := d.SeedTool("agents-bound-fixture", "bound", nil, json.RawMessage(`["reverse_dynamic"]`)); err != nil {
		t.Fatal(err)
	}
	want := json.RawMessage(`["reverse_static","reverse_dynamic","reverse_reviewer"]`)
	if err := d.EnsureToolAgents("agents-empty-fixture", want); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureToolAgents("agents-bound-fixture", want); err != nil {
		t.Fatal(err)
	}
	empty, err := d.GetTool("agents-empty-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Agents) != 3 {
		t.Fatalf("empty binding was not repaired: %+v", empty.Agents)
	}
	bound, err := d.GetTool("agents-bound-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if len(bound.Agents) != 1 || bound.Agents[0] != "reverse_dynamic" {
		t.Fatalf("operator binding was overwritten: %+v", bound.Agents)
	}
}
