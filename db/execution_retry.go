package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// A transient interruption gets one retry. Further automatic continuations
// require new saved progress and remain bounded by the task's existing budget.
const MaxAutomaticWorkRetries = 3

type workRetryState struct {
	Retries  int          `json:"planner_retries"`
	Progress string       `json:"planner_retry_progress"`
	Result   IntentResult `json:"execution_result"`
}

// Timestamps, attempt counters, retry reasons and paraphrased summaries do not
// establish progress. Checkpoints are retained so a long analysis can resume
// before it has a complete finding; the hard retry ceiling still applies.
func workRetryProgress(result IntentResult) string {
	checkpoint := strings.TrimSpace(result.Checkpoint)
	if checkpoint == "" && len(result.Evidence) == 0 {
		return ""
	}
	refs := append([]EvidenceReference(nil), result.Evidence...)
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].NodeID != refs[j].NodeID {
			return refs[i].NodeID < refs[j].NodeID
		}
		return refs[i].Version < refs[j].Version
	})
	raw, _ := json.Marshal(struct {
		Checkpoint string
		Evidence   []EvidenceReference
	}{checkpoint, refs})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
