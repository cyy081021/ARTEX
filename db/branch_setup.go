package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/artex/collab"
)

// BranchSetupSource is an internal, consistent snapshot. Capabilities and the
// digest must never be used as a public projection of device configuration.
type BranchSetupSource struct {
	Task struct {
		ID     int64  `json:"id"`
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		Goal   string `json:"goal"`
		Paused bool   `json:"paused"`
		Status string `json:"status"`
	} `json:"task"`
	Scopes      []TaskScope         `json:"scopes"`
	Assets      []BranchSetupAsset  `json:"assets"`
	Constraints []Constraint        `json:"constraints"`
	Materials   []ReverseArtifact   `json:"materials"`
	Devices     []BranchSetupDevice `json:"devices"`
	Shared      bool                `json:"shared"`
	Enabled     bool                `json:"enabled"`
	Digest      string              `json:"-"`
}

type BranchSetupAsset struct {
	ID     int64  `json:"id"`
	Target string `json:"target"`
}

type BranchSetupDevice struct {
	ID           int64           `json:"id"`
	Name         string          `json:"name"`
	MemberID     int64           `json:"member_id"`
	MemberName   string          `json:"member_name"`
	Active       bool            `json:"active"`
	Online       bool            `json:"online"`
	Permitted    bool            `json:"permitted"`
	Capabilities json.RawMessage `json:"capabilities"`
}

// One SQL statement gives preview and confirmation the same MVCC snapshot.
// Only this task's declared scope is used; inherited tasks and evidence anchors
// do not silently turn into execution authorization.
const branchSetupSourceSQL = `SELECT jsonb_build_object(
 'task',jsonb_build_object('id',t.id,'name',t.name,'kind',t.kind,'goal',t.goal,'paused',t.paused,'status',t.status),
 'shared',EXISTS(SELECT 1 FROM team_tasks WHERE team_id=$1 AND task_id=t.id),
 'enabled',EXISTS(SELECT 1 FROM team_branch_projects WHERE task_id=t.id),
 'scopes',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',s.id,'task_id',s.task_id,'kind',s.kind,'company_id',s.company_id,'company_name',COALESCE(c.name,''),'domain',COALESCE(s.domain,''),'net',COALESCE(s.net::text,''),'value',COALESCE(s.value,''),'source',s.source,'reason',COALESCE(s.reason,'')) ORDER BY s.id) FROM task_scope s LEFT JOIN companies c ON c.id=s.company_id WHERE s.task_id=t.id),'[]'::jsonb),
 'assets',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',a.id,'target',COALESCE(NULLIF(a.url,''),NULLIF(a.domain,''),NULLIF(a.ip,''),NULLIF(a.app_name,''),a.root_domain,'')) ORDER BY a.id) FROM (SELECT DISTINCT a.* FROM assets a JOIN task_scope s ON
    (s.kind='company' AND a.company_id=s.company_id)
 OR (s.kind='root_domain' AND a.root_domain=s.domain)
 OR (s.kind='subdomain' AND a.domain=s.domain)
 OR (s.kind IN ('ip','cidr') AND (s.net >>= try_inet(a.ip) OR s.net >>= try_inet(a.domain)))
 OR (s.kind='icp' AND (lower(regexp_replace(COALESCE(a.icp,''),'[[:space:]]+','','g'))=s.value OR lower(regexp_replace(COALESCE(a.app_icp,''),'[[:space:]]+','','g'))=s.value))
 WHERE s.task_id=t.id ORDER BY a.id LIMIT 257) a),'[]'::jsonb),
 'constraints',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',c.id,'kind',c.kind,'text',c.text,'origin',COALESCE(c.origin,'')) ORDER BY c.id) FROM task_constraints c WHERE c.exploration_id=t.exploration_id),'[]'::jsonb),
 'materials',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',a.id,'task_id',a.task_id,'name',a.name,'size_bytes',a.size_bytes,'sha256',a.sha256,'version',a.version) ORDER BY a.id) FROM reverse_artifacts a WHERE a.task_id=t.id),'[]'::jsonb),
 'devices',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',d.id,'name',d.name,'member_id',m.id,'member_name',m.login,'active',d.revoked_at IS NULL AND m.revoked_at IS NULL,'online',COALESCE(d.last_seen_at>now()-interval '30 seconds',false),'permitted',EXISTS(SELECT 1 FROM team_task_permissions p WHERE p.team_id=$1 AND p.task_id=t.id AND p.member_id=m.id AND p.permission='read') AND EXISTS(SELECT 1 FROM team_task_permissions p WHERE p.team_id=$1 AND p.task_id=t.id AND p.member_id=m.id AND p.permission='execute'),'capabilities',d.capabilities) ORDER BY d.id) FROM team_devices d JOIN team_members m ON m.id=d.owner_member_id WHERE d.team_id=$1),'[]'::jsonb)
) FROM tasks t WHERE t.id=$2 AND t.deleted_at IS NULL AND t.archived_at IS NULL`

type branchSetupQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func branchSetupSource(ctx context.Context, q branchSetupQuery, team, task int64) (*BranchSetupSource, error) {
	var raw []byte
	if err := q.QueryRowContext(ctx, branchSetupSourceSQL, team, task).Scan(&raw); err != nil {
		return nil, err
	}
	var v BranchSetupSource
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	v.Digest = collab.ContentHash(raw)
	return &v, nil
}

func (d *DB) BranchSetupSource(ctx context.Context, team, task int64) (*BranchSetupSource, error) {
	return branchSetupSource(ctx, d, team, task)
}

func checkBranchSetupSource(ctx context.Context, tx *sql.Tx, team, task int64, expected string) error {
	v, err := branchSetupSource(ctx, tx, team, task)
	if err != nil {
		return err
	}
	if v.Digest != expected {
		return fmt.Errorf("主任务、成员权限或设备配置已变化，请重新生成并核对配置")
	}
	return nil
}
