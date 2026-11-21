package db

import (
	"strings"
	"testing"
)

// A flag is compared exactly and deduped per task: a second submit during a
// competition is a duplicate, not an error, and it must not overwrite the first
// capture's source.
func TestTaskFlagDedupAndNormalization(t *testing.T) {
	d, _, _ := executionFixture(t)
	task, err := d.CreateTaskWithOptions("flag fixture", "offline synthetic test", TaskCreateOptions{Kind: "pentest", Mode: "ctf"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExplorationID)
	})

	first, isNew, err := d.AddTaskFlag(task.ID, 7, "  flag{abc}  ", "GET /admin HTTP/1.1 200", "控制台提示")
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Fatal("first capture must be new")
	}
	if first.Value != "flag{abc}" {
		t.Fatalf("normalization failed: %q", first.Value)
	}
	again, isNew, err := d.AddTaskFlag(task.ID, 8, "flag{abc}", "second source", "")
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Fatal("duplicate submit reported as new")
	}
	if again.ID != first.ID || again.Source != "GET /admin HTTP/1.1 200" {
		t.Fatalf("duplicate overwrote the first capture: %+v", again)
	}
	other, isNew, err := d.AddTaskFlag(task.ID, 9, "flag{ABC}", "case variant", "")
	if err != nil {
		t.Fatal(err)
	}
	if !isNew || other.ID == first.ID {
		t.Fatal("a case variant must be a separate flag")
	}
	list, err := d.ListTaskFlags(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 flags, got %d", len(list))
	}
	for _, bad := range []string{"", "   ", "a\nb", strings.Repeat("x", 600)} {
		if _, _, err := d.AddTaskFlag(task.ID, 0, bad, "", ""); err == nil {
			t.Fatalf("accepted invalid flag %q", bad)
		}
	}

	// The cross-task board reads every live task's flags in one query; it must carry
	// the task identity so the operator can tell which challenge it came from.
	board, err := d.ListAllFlags(50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, row := range board {
		if row.TaskID == task.ID {
			seen[row.Value] = true
			// An unnamed task keeps an empty name here; the UI falls back to "#id".
			if row.TaskMode != "ctf" {
				t.Fatalf("board row lost task identity: %+v", row)
			}
		}
	}
	if !seen["flag{abc}"] || !seen["flag{ABC}"] {
		t.Fatalf("board is missing this task's flags: %+v", seen)
	}
}
