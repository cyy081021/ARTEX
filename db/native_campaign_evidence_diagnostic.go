package db

import (
 "context"
 "database/sql"
 "errors"
 "time"
)

// EvidenceDiagnosticSnapshot is an observation, never deletion permission.
// References include unpublished metadata; the snapshot is not held during IO.
type EvidenceDiagnosticSnapshot struct {
 TaskID, CampaignID int64
 ObservedAt time.Time
 Eligible bool
 Attempts map[int64]bool
 Paths, Hashes map[string]bool
}

func (d *DB) ReadEvidenceDiagnosticSnapshot(ctx context.Context, taskID, campaignID int64) (*EvidenceDiagnosticSnapshot, error) {
 ctx,cancel:=context.WithTimeout(ctx,5*time.Second);defer cancel()
 if taskID <= 0 || campaignID <= 0 { return nil, errors.New("invalid diagnostic scope") }
 tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
 if err != nil { return nil, err }; defer tx.Rollback()
 s := &EvidenceDiagnosticSnapshot{TaskID:taskID, CampaignID:campaignID, Attempts:map[int64]bool{}, Paths:map[string]bool{}, Hashes:map[string]bool{}}
 var blocked bool
 err = tx.QueryRowContext(ctx, `SELECT transaction_timestamp(),
 t.deleted_at IS NOT NULL OR t.archived_at IS NOT NULL
 OR EXISTS(SELECT 1 FROM task_archives WHERE task_id=t.id)
 OR EXISTS(SELECT 1 FROM native_campaign_events WHERE task_id=t.id AND kind='campaign.archive_restored')
 OR EXISTS(SELECT 1 FROM native_campaigns WHERE task_id=t.id AND state IN ('queued','running','stopping'))
 OR EXISTS(SELECT 1 FROM native_campaign_attempts WHERE task_id=t.id AND
 (resource_hold OR state NOT IN ('paused','completed','cancelled','failed','interrupted') OR ended_at IS NULL))
 FROM tasks t JOIN native_campaigns c ON c.task_id=t.id AND c.id=$2 WHERE t.id=$1`, taskID,campaignID).Scan(&s.ObservedAt,&blocked)
 if err != nil { return nil, err }
 if blocked { return s, tx.Commit() }
 rows,err := tx.QueryContext(ctx, `SELECT id FROM native_campaign_attempts WHERE task_id=$1 AND campaign_id=$2 ORDER BY id LIMIT 1025`,taskID,campaignID)
 if err != nil { return nil,err }
 for rows.Next(){ var id int64; if err=rows.Scan(&id);err!=nil{rows.Close();return nil,err};s.Attempts[id]=true }
 err=rows.Err();rows.Close();if err!=nil{return nil,err};if len(s.Attempts)>1024{return nil,errors.New("diagnostic attempt bound exceeded")}
 rows,err=tx.QueryContext(ctx,`SELECT result_path,sha256 FROM native_campaign_evidence WHERE task_id=$1 ORDER BY id LIMIT 1025`,taskID)
 if err!=nil{return nil,err};count:=0
 for rows.Next(){var path,hash string;if err=rows.Scan(&path,&hash);err!=nil{rows.Close();return nil,err};count++;s.Paths[path]=true;s.Hashes[hash]=true}
 err=rows.Err();rows.Close();if err!=nil{return nil,err};if count>1024{return nil,errors.New("diagnostic reference bound exceeded")}
 s.Eligible=true
 if err=tx.Commit();err!=nil{return nil,err};return s,nil
}
