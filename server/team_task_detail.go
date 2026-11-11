package server

import (
	"net/http"
	"time"
)

// teamTaskDetail is a deliberately small projection of a shared task. The
// legacy task API includes administration/configuration fields and is not part
// of the member listener's surface.
func (s *Server) teamTaskDetail(w http.ResponseWriter, r *http.Request) {
	p, team, t, ok := s.teamTaskScope(w, r, "read")
	if !ok {
		return
	}
	permissions := map[string]bool{"read": true}
	for _, permission := range []string{"execute", "manage", "review"} {
		permissions[permission] = p.Admin || s.m.pg.CheckTeamTaskPermission(r.Context(), team, t.ID, p.MemberID, permission) == nil
	}
	task := map[string]any{
		"id": t.ID, "name": t.Name, "kind": t.Kind, "goal": t.Goal,
		"status": t.Status, "paused": t.Paused, "queued": t.Queued,
		"created_at": t.CreatedAt.Format(time.RFC3339),
	}
	if t.CompletedAt != nil {
		task["completed_at"] = t.CompletedAt.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"task": task, "permissions": permissions, "is_admin": p.Admin, "member_id": p.MemberID,
	})
}
