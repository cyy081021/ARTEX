package collab

import (
	"strconv"
	"strings"
)

// The reviewer is a separate model session. Its conclusion can accept evidence
// into the project, but cannot assert that the main task has been completed.
type BranchReviewAssessment struct {
	Decision         string            `json:"decision"` // accept | needs_human
	Reason           string            `json:"reason"`
	AcceptanceMet    bool              `json:"acceptance_met"`
	EvidenceVersions map[string]string `json:"evidence_versions"`
	Uncertainties    []string          `json:"uncertainties"`
}

func automaticBranchReview(b *ExecutionBranch) (bool, string) {
	var reviewer *BranchUnit
	for i := range b.Units {
		u := &b.Units[i]
		if u.State == "candidate" && (u.Spec.Role == "reviewer" || u.Spec.Role == "reverse_reviewer") && u.Result != nil && u.Result.Review != nil {
			if reviewer == nil || u.ID > reviewer.ID {
				reviewer = u
			}
		}
	}
	if reviewer == nil {
		return false, "核验结果未给出明确判断，转人工复审"
	}
	r := reviewer.Result.Review
	reason := []rune(r.Reason)
	if len(reason) > 1000 {
		reason = reason[:1000]
	}
	if r.Decision != "accept" || !r.AcceptanceMet || len(r.Uncertainties) > 0 {
		return false, "核验存在疑点，转人工复审：" + string(reason)
	}
	if strings.TrimSpace(r.Reason) == "" || len(r.Reason) > 8000 {
		return false, "核验依据不完整，转人工复审"
	}
	checked := 0
	for _, u := range b.Units {
		if u.State == "superseded" || u.Spec.Role == "reviewer" || u.Spec.Role == "reverse_reviewer" {
			continue
		}
		if !hasID(reviewer.Spec.DependsOn, u.ID) || r.EvidenceVersions[strconv.FormatInt(u.ID, 10)] != u.EvidenceVersion {
			return false, "执行结果与核验版本不一致，转人工复审"
		}
		if u.Result == nil || u.Result.Outcome != "candidate" || len(u.Result.Evidence) == 0 {
			return false, "执行结果缺少可核对证据，转人工复审"
		}
		checked++
	}
	if checked == 0 {
		return false, "没有已核验的执行结果，转人工复审"
	}
	return true, r.Reason
}
