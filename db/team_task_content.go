package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// A shared task includes its explicitly attached, direct source context, just
// like the ordinary task reader. Never expand the sources recursively.
const teamTaskFindingScope = `(f.task_id=$1 OR f.task_id IN (SELECT source.id FROM task_relations r JOIN tasks source ON source.id=r.source_task_id AND source.deleted_at IS NULL WHERE r.task_id=$1))`

func contentSearch(q string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.TrimSpace(q)) + "%"
}

func (d *DB) TeamTaskFindings(ctx context.Context, task int64, query string, page, size int) ([]*DBFinding, int, error) {
	where := ` WHERE f.merged_into IS NULL AND ` + teamTaskFindingScope + ` AND concat_ws(' ',f.name,f.vulnclass,f.summary,f.severity,f.status) ILIKE $2 ESCAPE '\'`
	args := []any{task, contentSearch(query)}
	var total int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM findings f`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if total == 0 || page > (total-1)/size+1 {
		return []*DBFinding{}, total, nil
	}
	args = append(args, size, (page-1)*size)
	rows, err := d.QueryContext(ctx, `SELECT `+findingSelectCols+` FROM findings f LEFT JOIN tasks t ON t.id=f.task_id`+where+` ORDER BY f.id DESC LIMIT $3 OFFSET $4`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items, err := scanFindings(rows)
	return items, total, err
}

func (d *DB) TeamTaskFinding(ctx context.Context, task, id int64) (*DBFinding, error) {
	var allowed bool
	if err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM findings f WHERE f.id=$2 AND `+teamTaskFindingScope+`)`, task, id).Scan(&allowed); err != nil {
		return nil, err
	}
	if !allowed {
		return nil, sql.ErrNoRows
	}
	f, err := d.GetFinding(id)
	if err == nil && f == nil {
		return nil, sql.ErrNoRows
	}
	return f, err
}

func (d *DB) TeamTaskRetests(ctx context.Context, task int64, query string, page, size int) ([]*FindingRetest, int, error) {
	where := ` FROM finding_retests r JOIN findings f ON f.id=r.finding_id WHERE ` + teamTaskFindingScope + ` AND concat_ws(' ',f.name,r.summary,r.verdict,r.status,r.notes) ILIKE $2 ESCAPE '\'`
	var total int
	if err := d.QueryRowContext(ctx, `SELECT count(*)`+where, task, contentSearch(query)).Scan(&total); err != nil {
		return nil, 0, err
	}
	out := []*FindingRetest{}
	if total == 0 || page > (total-1)/size+1 {
		return out, total, nil
	}
	rows, err := d.QueryContext(ctx, `SELECT r.id,r.finding_id,r.conversation_id,r.status,r.verdict,r.notes,r.summary,r.evidence,r.error,r.created_at,r.started_at,r.finished_at`+where+` ORDER BY r.id DESC LIMIT $3 OFFSET $4`, task, contentSearch(query), size, (page-1)*size)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		r, e := scanRetest(rows)
		if e != nil {
			return nil, 0, e
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func (d *DB) TeamTaskAssets(ctx context.Context, task int64, query string, page, size int) ([]Asset, int, error) {
	where := ` FROM assets a WHERE $1=ANY(a.task_ids) AND concat_ws(' ',a.type,a.url,a.domain,a.ip,a.app_name,a.root_domain,a.page_title,a.service_type) ILIKE $2 ESCAPE '\'`
	var total int
	if err := d.QueryRowContext(ctx, `SELECT count(*)`+where, task, contentSearch(query)).Scan(&total); err != nil {
		return nil, 0, err
	}
	out := []Asset{}
	if total == 0 || page > (total-1)/size+1 {
		return out, total, nil
	}
	rows, err := d.QueryContext(ctx, `SELECT to_jsonb(a)`+where+` ORDER BY a.last_seen DESC,a.id DESC LIMIT $3 OFFSET $4`, task, contentSearch(query), size, (page-1)*size)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var a Asset
		if err = rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		if err = json.Unmarshal(raw, &a); err != nil {
			return nil, 0, fmt.Errorf("asset projection: %w", err)
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func (d *DB) TeamTaskAsset(ctx context.Context, task, id int64) (*Asset, error) {
	var raw []byte
	if err := d.QueryRowContext(ctx, `SELECT to_jsonb(a) FROM assets a WHERE a.id=$2 AND $1=ANY(a.task_ids)`, task, id).Scan(&raw); err != nil {
		return nil, err
	}
	var a Asset
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	return &a, nil
}
