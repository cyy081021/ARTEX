package db

import "testing"

func TestAcceptanceCompatibleReceiptStillRequiresEveryCriterion(t *testing.T) {
	c := WorkContract{Acceptance: []string{"first observation", "second observation"}}
	criteria := AcceptanceCriteria(c)
	ids := []string{criteria[0].ID, criteria[1].ID}
	if err := validateSatisfied(c, IntentResult{SatisfiedIDs: ids, Satisfied: c.Acceptance}); err != nil {
		t.Fatalf("consistent compatibility fields rejected: %v", err)
	}
	for _, result := range []IntentResult{
		{SatisfiedIDs: ids, Satisfied: []string{"first observation"}},
		{SatisfiedIDs: ids, Satisfied: []string{"first observation", "invented condition"}},
		{SatisfiedIDs: ids[:1], Satisfied: c.Acceptance[:1]},
		{SatisfiedIDs: []string{criteria[0].ID, criteria[0].ID}, Satisfied: c.Acceptance},
		{SatisfiedIDs: []string{"invented"}, Satisfied: c.Acceptance},
	} {
		if err := validateSatisfied(c, result); err == nil {
			t.Fatalf("incomplete or contradictory receipt accepted: %#v", result)
		}
	}
}
