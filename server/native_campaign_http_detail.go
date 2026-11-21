package server

import (
	"net/http"
)

// nativeCampaignHTTPAttempts lists attempts of one campaign (newest first), with the
// facts an operator needs to judge a stalled or paused campaign: state, hold, budget,
// cleanup and the checkpoint an attempt produced.
func (s *Server) nativeCampaignHTTPAttempts(w http.ResponseWriter, r *http.Request) {
	service, taskID, ok := s.nativeCampaignHTTPRead(w, r)
	if !ok {
		return
	}
	campaignID, err := nativeCampaignHTTPInteger(r.PathValue("campaign_id"), 1, 1<<63-1)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	q, err := nativeCampaignHTTPQuery(r, "before_id", "limit")
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	before, err := nativeCampaignHTTPQueryInt(q, "before_id", 0, 0, 1<<63-1)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	limit, err := nativeCampaignHTTPQueryInt(q, "limit", 50, 1, 100)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	// Ownership is checked before the rows are served: an attempt of another campaign
	// must never be readable through this path.
	if _, err = service.loadCampaign(r.Context(), taskID, campaignID); err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	rows, err := service.pg.NativeCampaignAttempts(r.Context(), taskID, campaignID, int(limit), before)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, a := range rows {
		out = append(out, map[string]any{
			"id": a.ID, "attempt_no": a.AttemptNo, "state": a.State, "phase": a.Phase,
			"fencing_token": a.FencingToken, "worker_slot": a.WorkerSlot,
			"lease_owner": a.LeaseOwner, "resource_hold": a.ResourceHold,
			"hold_reason":        a.HoldReason,
			"reserved_budget_ms": a.ReservedBudgetMS, "charged_budget_ms": a.ChargedBudgetMS,
			"actual_elapsed_ms": a.ActualElapsedMS, "cleanup_status": a.CleanupStatus,
			"checkpoint_id": a.CheckpointID, "termination_reason": a.TerminationReason,
			"budget_overrun": a.BudgetOverrun,
			"started_at":     a.StartedAt, "ended_at": a.EndedAt, "created_at": a.CreatedAt,
		})
	}
	var next any
	if len(rows) == int(limit) && len(rows) > 0 {
		next = rows[len(rows)-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"attempts": out, "next_before_id": next, "candidate_only": true,
	})
}

// nativeCampaignHTTPCheckpoints lists the durable corpus checkpoints of one campaign.
func (s *Server) nativeCampaignHTTPCheckpoints(w http.ResponseWriter, r *http.Request) {
	service, taskID, ok := s.nativeCampaignHTTPRead(w, r)
	if !ok {
		return
	}
	campaignID, err := nativeCampaignHTTPInteger(r.PathValue("campaign_id"), 1, 1<<63-1)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	q, err := nativeCampaignHTTPQuery(r, "before_id", "limit")
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	before, err := nativeCampaignHTTPQueryInt(q, "before_id", 0, 0, 1<<63-1)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	limit, err := nativeCampaignHTTPQueryInt(q, "limit", 50, 1, 100)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	if _, err = service.loadCampaign(r.Context(), taskID, campaignID); err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	rows, err := service.pg.NativeCampaignCheckpoints(r.Context(), taskID, campaignID, int(limit), before)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		out = append(out, map[string]any{
			"id": c.ID, "attempt_id": c.AttemptID, "state": c.State,
			"format_version": c.FormatVersion, "entry_count": c.EntryCount,
			"total_bytes": c.TotalBytes, "manifest_id": c.ManifestID,
			"truncated": c.Truncated, "created_at": c.CreatedAt, "verified_at": c.VerifiedAt,
		})
	}
	var next any
	if len(rows) == int(limit) && len(rows) > 0 {
		next = rows[len(rows)-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"checkpoints": out, "next_before_id": next, "candidate_only": true,
	})
}
