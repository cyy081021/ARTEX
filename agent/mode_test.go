package agent

import (
	"context"
	"strings"
	"testing"
)

func TestModeContextDefaultsToNormal(t *testing.T) {
	if ModeOf(context.Background()) != ModeNormal || IsCTF(context.Background()) {
		t.Fatal("a zero context must stay in normal mode")
	}
	for _, mode := range []string{"", "normal", "bogus"} {
		if ModeOf(WithMode(context.Background(), mode)) != ModeNormal {
			t.Fatalf("mode %q must fall back to normal", mode)
		}
	}
	if !IsCTF(WithMode(context.Background(), ModeCTF)) {
		t.Fatal("ctf mode must be reachable")
	}
}

func TestCTFOverlayIsAdditiveAndRoleSpecific(t *testing.T) {
	planner := ctfOverlay("planner")
	if !strings.Contains(planner, "时间盒") || !strings.Contains(planner, "换路线") {
		t.Fatalf("planner overlay lost the CTF rules: %q", planner)
	}
	goals := ctfOverlay("goals")
	if !strings.Contains(goals, "flag") || !strings.Contains(goals, "prove_goal") {
		t.Fatalf("goals overlay lost the flag acceptance rule: %q", goals)
	}
	if !strings.Contains(ctfOverlay("worker"), "record_fact") {
		t.Fatal("worker overlay must say where the flag goes")
	}
	if !strings.Contains(ctfOverlay("reviewer"), "flag") {
		t.Fatal("reviewer overlay must scope review to the flag")
	}
	if ctfOverlay("unknown-role") != "" {
		t.Fatal("unknown roles must not get an overlay")
	}
	// The overlay is additive: normal-mode policy text stays in the base prompts.
	if !strings.Contains(plannerDefaultTmpl, "硬底线") {
		t.Fatal("normal planner policy must survive CTF mode")
	}
	if !IsReverse(WithWorkflow(context.Background(), "reverse")) {
		t.Fatal("mode plumbing must not disturb workflow selection")
	}
}
