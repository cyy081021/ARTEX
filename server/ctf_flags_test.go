package server

import "testing"

// The flag surface is CTF-only and role-scoped: a capture happens in an executing
// role, everyone may read the ledger, and no other role gets the write tool.
func TestCTFFlagToolSurfaceAndRoles(t *testing.T) {
	tools := ctfFlagTools(nil, 0)
	if len(tools) != 2 {
		t.Fatalf("expected submit_flag and list_flags, got %d", len(tools))
	}
	names := map[string]bool{}
	for _, tool := range tools {
		names[tool.Name()] = true
		if tool.Description() == "" || len(tool.InputSchema()) == 0 {
			t.Fatalf("%s lacks description/schema", tool.Name())
		}
	}
	if !names["submit_flag"] || !names["list_flags"] {
		t.Fatalf("unexpected tool names: %+v", names)
	}
	for _, role := range []string{"worker", "reverse_static", "reverse_dynamic"} {
		if !ctfFlagAllowed(role, "submit_flag") {
			t.Fatalf("%s must be able to submit a flag", role)
		}
	}
	for _, role := range []string{"planner", "reverse_planner", "reverse_main", "reverse_goals", "reverse_reviewer"} {
		if ctfFlagAllowed(role, "submit_flag") {
			t.Fatalf("%s must not write the flag ledger", role)
		}
		if !ctfFlagAllowed(role, "list_flags") {
			t.Fatalf("%s must still be able to read the ledger", role)
		}
	}
	if ctfFlagAllowed("worker", "some_other_tool") {
		t.Fatal("the flag policy must not authorise unrelated tools")
	}
}
