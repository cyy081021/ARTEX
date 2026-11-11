package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/collab"
)

func dispatchBranchesTx(ctx context.Context, tx *sql.Tx, p *collab.BranchProject) ([]collab.BranchEvent, error) {
	if !p.Policy.AutoDispatch || p.State != "running" {
		return nil, nil
	}
	source, err := branchSetupSource(ctx, tx, p.TeamID, p.TaskID)
	if err != nil {
		return nil, err
	}
	if source.Task.Paused || IsTerminal(source.Task.Status) || source.Task.Status == "finalizing" {
		return nil, nil
	}
	devices := map[int64]collab.BranchDevice{}
	for _, v := range source.Devices {
		if !v.Active || !v.Online || !v.Permitted {
			continue
		}
		var c struct {
			Protocol         int                      `json:"branch_protocol"`
			Enabled          bool                     `json:"execution_enabled"`
			Roles            []string                 `json:"roles"`
			RoleCapabilities map[string][]string      `json:"role_capabilities"`
			Report           collab.BranchSetupReport `json:"branch_setup"`
		}
		if json.Unmarshal(v.Capabilities, &c) != nil || !c.Enabled || c.Protocol != collab.BranchProtocol || c.Report.Version != 1 {
			continue
		}
		approved, ok := p.Policy.DeviceRoles[strconv.FormatInt(v.ID, 10)]
		if !ok {
			continue
		}
		ready := true
		for role, caps := range approved {
			entry := c.Report.Roles[role]
			if !entry.Ready {
				ready = false
				break
			}
			for _, cap := range caps {
				if !slices.Contains(entry.Capabilities, cap) {
					ready = false
					break
				}
			}
		}
		if !ready {
			continue
		}
		devices[v.ID] = collab.BranchDevice{ID: v.ID, OwnerID: v.MemberID, Active: true, Online: true, Protocol: c.Protocol, Roles: c.Roles, RoleCapabilities: c.RoleCapabilities}
	}
	return collab.DispatchBranches(p, devices, time.Now().UTC())
}

// Shared by explicit commands and device polling so automatic dispatch retains
// the same durable event stream and task->project transaction lock order.
func persistBranchProjectTx(ctx context.Context, tx *sql.Tx, p *collab.BranchProject, events []collab.BranchEvent) error {
	for _, ev := range events {
		p.Cursor++
		ev.ID = p.Cursor
		ev.CreatedAt = time.Now().UTC()
		raw, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO team_branch_events(task_id,seq,branch_id,event) VALUES($1,$2,$3,$4)`, p.TaskID, ev.ID, ev.BranchID, raw); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(raw) > 32<<20 {
		return collab.ErrBranchInvalid
	}
	_, err = tx.ExecContext(ctx, `UPDATE team_branch_projects SET state=$2,updated_at=now() WHERE task_id=$1`, p.TaskID, raw)
	return err
}
