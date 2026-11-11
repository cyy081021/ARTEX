package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func retryCheckpoint(t *testing.T, s *ExplorationStore, id int64, checkpoint string, evidence []EvidenceReference) {
	t.Helper()
	attempt := executionAttempt(t, s, id)
	r := IntentResult{Outcome: "incomplete", Summary: "fixture progress", Remaining: []string{"finish fixture"}, Checkpoint: checkpoint, Evidence: evidence}
	if err := s.SubmitIntentResult(t.Context(), id, attempt, r); err != nil {
		t.Fatal(err)
	}
	if state, err := s.FinishIntentAttempt(t.Context(), id, attempt, "exhausted"); err != nil || state != "exhausted" {
		t.Fatalf("finish %s: %v", state, err)
	}
}

func TestAutomaticWorkRetryProgressAndCeiling(t *testing.T) {
	_, _, s := executionFixture(t)
	id := executionWork(t, s, "long fixture analysis", WorkContract{Acceptance: []string{"finish fixture"}, BudgetSeconds: 30})
	for i := 0; i < MaxAutomaticWorkRetries; i++ {
		retryCheckpoint(t, s, id, fmt.Sprintf("completed fixture section %d", i), nil)
		if err := s.RetryWorkIntent(t.Context(), id, "resume next section"); err != nil {
			t.Fatalf("progress retry %d: %v", i+1, err)
		}
	}
	retryCheckpoint(t, s, id, "new section beyond automatic ceiling", nil)
	if err := s.RetryWorkIntent(t.Context(), id, "progress exists"); err == nil || !strings.Contains(err.Error(), "3 次") {
		t.Fatalf("retry ceiling not enforced: %v", err)
	}
	n, _ := s.GetNode(id)
	var saved workRetryState
	_ = json.Unmarshal(n.Payload, &saved)
	contract, attempt := IntentContract(n)
	if saved.Retries != 3 || contract.BudgetSeconds != 30 || attempt != 4 || n.State != "exhausted" {
		t.Fatalf("continuation reset accounting/contract/state: %s", n.Payload)
	}
}

func TestAutomaticWorkRetryRejectsRewordingAndAcceptsNewEvidence(t *testing.T) {
	d, _, s := executionFixture(t)
	id := executionWork(t, s, "progress fixture", WorkContract{Acceptance: []string{"finish fixture"}})
	retryCheckpoint(t, s, id, "read section one", nil)
	if err := s.RetryWorkIntent(t.Context(), id, "continue"); err != nil {
		t.Fatal(err)
	}
	retryCheckpoint(t, s, id, "read section one", nil)
	if err := s.RetryWorkIntent(t.Context(), id, "different reason is not new progress"); err == nil {
		t.Fatal("unchanged progress accepted")
	}
	ref := executionEvidence(t, s)
	r := IntentResult{Outcome: "incomplete", Summary: "new saved evidence", Remaining: []string{"finish fixture"}, Checkpoint: "read section one", Evidence: []EvidenceReference{ref}}
	raw, _ := json.Marshal(r)
	if _, err := d.Exec(`UPDATE exploration_nodes SET payload=jsonb_set(payload,'{execution_result}',$2::jsonb) WHERE id=$1`, id, raw); err != nil {
		t.Fatal(err)
	}
	if err := s.RetryWorkIntent(t.Context(), id, "resume with new saved evidence"); err != nil {
		t.Fatal(err)
	}
}

func TestAutomaticWorkRetryLegacyAndConcurrentAdmission(t *testing.T) {
	d, _, s := executionFixture(t)
	id := executionWork(t, s, "legacy continuation", WorkContract{})
	retryCheckpoint(t, s, id, "legacy saved checkpoint", nil)
	if _, err := d.Exec(`UPDATE exploration_nodes SET payload=payload||'{"planner_retries":1}'::jsonb WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.RetryWorkIntent(t.Context(), id, "legacy checkpoint can continue") == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("duplicate retry admission: %d", successes.Load())
	}
}

func TestRetryProgressIgnoresEvidenceOrderAndSummary(t *testing.T) {
	a := IntentResult{Checkpoint: "ready", Evidence: []EvidenceReference{{NodeID: 2, Version: "b"}, {NodeID: 1, Version: "a"}}}
	b := a
	b.Summary = "different wording"
	b.Attempt = 100
	b.Evidence = []EvidenceReference{a.Evidence[1], a.Evidence[0]}
	if workRetryProgress(a) != workRetryProgress(b) {
		t.Fatal("non-progress fields reset retry gate")
	}
}
