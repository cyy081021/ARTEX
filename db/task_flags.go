package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// TaskFlag is one captured flag for a CTF-mode task. The raw value is kept
// because the operator has to read and copy it; the SHA-256 is what dedupes
// repeated submissions without comparing secrets in SQL.
type TaskFlag struct {
	ID        int64     `json:"id"`
	TaskID    int64     `json:"task_id"`
	IntentID  int64     `json:"intent_id,omitempty"`
	Value     string    `json:"value"`
	SHA256    string    `json:"sha256"`
	Source    string    `json:"source"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

const maxFlagLength = 512

// NormalizeFlag trims surrounding whitespace only. A flag is compared exactly:
// "flag{a}" and "flag{A}" are different submissions, and so are two case variants
// from different challenge instances.
func NormalizeFlag(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", errors.New("flag 不能为空")
	}
	if len(v) > maxFlagLength {
		return "", errors.New("flag 超过 512 字节")
	}
	if strings.ContainsAny(v, "\r\n\t") {
		return "", errors.New("flag 必须是单行，且不含制表符")
	}
	return v, nil
}

func flagDigest(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// AddTaskFlag records a first capture and reports duplicates instead of failing:
// a repeated submit is normal during a competition, not an error.
func (d *DB) AddTaskFlag(taskID, intentID int64, raw, source, note string) (*TaskFlag, bool, error) {
	v, err := NormalizeFlag(raw)
	if err != nil {
		return nil, false, err
	}
	if len(source) > 2048 {
		source = source[:2048]
	}
	if len(note) > 2048 {
		note = note[:2048]
	}
	digest := flagDigest(v)
	var existing TaskFlag
	err = d.QueryRow(`SELECT id,task_id,intent_id,value,flag_sha256,source,note,created_at FROM task_flags WHERE task_id=$1 AND flag_sha256=$2`, taskID, digest).
		Scan(&existing.ID, &existing.TaskID, &existing.IntentID, &existing.Value, &existing.SHA256, &existing.Source, &existing.Note, &existing.CreatedAt)
	if err == nil {
		return &existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	var out TaskFlag
	err = d.QueryRow(`INSERT INTO task_flags(task_id,intent_id,flag_sha256,value,source,note) VALUES($1,$2,$3,$4,$5,$6)
RETURNING id,task_id,intent_id,value,flag_sha256,source,note,created_at`, taskID, intentID, digest, v, source, note).
		Scan(&out.ID, &out.TaskID, &out.IntentID, &out.Value, &out.SHA256, &out.Source, &out.Note, &out.CreatedAt)
	if err != nil {
		// A concurrent submit of the same flag loses the insert race; return the winner.
		var raced TaskFlag
		if e := d.QueryRow(`SELECT id,task_id,intent_id,value,flag_sha256,source,note,created_at FROM task_flags WHERE task_id=$1 AND flag_sha256=$2`, taskID, digest).
			Scan(&raced.ID, &raced.TaskID, &raced.IntentID, &raced.Value, &raced.SHA256, &raced.Source, &raced.Note, &raced.CreatedAt); e == nil {
			return &raced, false, nil
		}
		return nil, false, err
	}
	return &out, true, nil
}

// TaskFlagRow is one flag together with the task that captured it, for the
// cross-task board an operator watches during a competition.
type TaskFlagRow struct {
	TaskFlag
	TaskName string `json:"task_name"`
	TaskMode string `json:"task_mode"`
}

// ListAllFlags returns the newest flags across live tasks. A competition runs many
// challenge tasks at once, so the board has to read them in one query.
func (d *DB) ListAllFlags(limit int) ([]TaskFlagRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := d.Query(`SELECT f.id,f.task_id,f.intent_id,f.value,f.flag_sha256,f.source,f.note,f.created_at,
       COALESCE(t.name,''),COALESCE(t.mode,'normal')
  FROM task_flags f
  JOIN tasks t ON t.id=f.task_id
 WHERE t.deleted_at IS NULL
 ORDER BY f.created_at DESC, f.id DESC
 LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskFlagRow{}
	for rows.Next() {
		var r TaskFlagRow
		if err := rows.Scan(&r.ID, &r.TaskID, &r.IntentID, &r.Value, &r.SHA256, &r.Source, &r.Note, &r.CreatedAt, &r.TaskName, &r.TaskMode); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) ListTaskFlags(taskID int64) ([]TaskFlag, error) {
	rows, err := d.Query(`SELECT id,task_id,intent_id,value,flag_sha256,source,note,created_at FROM task_flags WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskFlag{}
	for rows.Next() {
		var f TaskFlag
		if err := rows.Scan(&f.ID, &f.TaskID, &f.IntentID, &f.Value, &f.SHA256, &f.Source, &f.Note, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
