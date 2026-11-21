package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"
)

// Native Campaign v1 (T3) canonical request identity and idempotency.
//
// Mutation commands share one transaction with their native_campaign_requests
// row. A same-request_id/same-hash replay returns the stored response and never
// repeats state or budget side effects; a different hash is
// idempotency_conflict. Deterministic 2xx/4xx responses are stored, while 5xx
// and rolled-back transactions leave no row so a retry is allowed.

type nativeCampaignRequestFlags struct {
	alreadyQueued    bool
	alreadyPaused    bool
	alreadyFinalized bool
}

type nativeCampaignMutationFunc func(context.Context, *sql.Tx) (int, any, nativeCampaignRequestFlags, error)

type nativeCampaignRequestLockWaitKey struct{}

func withNativeCampaignRequestLockWait(ctx context.Context, wait time.Duration) context.Context {
	return context.WithValue(ctx, nativeCampaignRequestLockWaitKey{}, wait)
}

func nativeCampaignRequestLockWait(ctx context.Context) time.Duration {
	if wait, ok := ctx.Value(nativeCampaignRequestLockWaitKey{}).(time.Duration); ok && wait > 0 {
		return wait
	}
	return 3 * time.Second
}

type nativeCampaignFaultKey struct{}

// withNativeCampaignFault is a synthetic test/fault-injection seam. It is
// intentionally context-scoped so production callers cannot accidentally
// install a global fault.
func withNativeCampaignFault(ctx context.Context, fn func(action string) error) context.Context {
	return context.WithValue(ctx, nativeCampaignFaultKey{}, fn)
}

func nativeCampaignFault(ctx context.Context, action string) error {
	if fn, ok := ctx.Value(nativeCampaignFaultKey{}).(func(string) error); ok && fn != nil {
		return fn(action)
	}
	return nil
}

var nativeCampaignActions = map[string]struct{}{
	"create":          {},
	"validate":        {},
	"start":           {},
	"status":          {},
	"list":            {},
	"pause":           {},
	"cancel":          {},
	"resume":          {},
	"export_manifest": {},
}

var nativeCampaignMutationActions = map[string]struct{}{
	"create": {},
	"start":  {},
	"pause":  {},
	"cancel": {},
	"resume": {},
}

var nativeCampaignActionFields = map[string]map[string]struct{}{
	"create": {
		"request_id": {}, "artifact_id": {}, "profile_id": {}, "argv": {},
		"input_mode": {}, "seeds": {}, "max_executions": {}, "max_crashes": {},
		"total_budget_ms": {}, "default_attempt_budget_ms": {},
	},
	"validate": {"campaign_id": {}},
	"start": {
		"request_id": {}, "campaign_id": {}, "expected_state_version": {}, "attempt_budget_ms": {},
	},
	"status":          {"campaign_id": {}, "include_events": {}},
	"list":            {"before_id": {}, "limit": {}},
	"pause":           {"request_id": {}, "campaign_id": {}, "expected_state_version": {}, "reason": {}},
	"cancel":          {"request_id": {}, "campaign_id": {}, "expected_state_version": {}, "reason": {}},
	"resume":          {"request_id": {}, "campaign_id": {}, "expected_state_version": {}, "attempt_budget_ms": {}},
	"export_manifest": {"campaign_id": {}, "checkpoint_id": {}, "max_entries": {}},
}

// ValidateNativeCampaignActionFields applies the 9-action whitelist and rejects
// unknown/cross-action fields. It is deliberately independent of the wire
// decoder so tests and future HTTP layers share one list.
func ValidateNativeCampaignActionFields(action string, payload map[string]any) error {
	if _, ok := nativeCampaignActions[action]; !ok {
		return nativeCampaignErrorf("unknown_action", 400, "unknown campaign action %q", action)
	}
	allowed := nativeCampaignActionFields[action]
	for key, value := range payload {
		if key == "action" {
			text, ok := value.(string)
			if !ok || text != action {
				return nativeCampaignErrorf("invalid_request", 400, "action field does not match the decoded action")
			}
			continue
		}
		if _, ok := allowed[key]; !ok {
			return nativeCampaignErrorf("unknown_field", 400, "field %q is not valid for action %q", key, action)
		}
	}
	if _, mutation := nativeCampaignMutationActions[action]; mutation {
		if _, ok := payload["request_id"]; !ok {
			return nativeCampaignErrorf("invalid_request", 400, "request_id is required for %s", action)
		}
	}
	switch action {
	case "create":
		for _, required := range []string{"artifact_id", "profile_id", "total_budget_ms"} {
			if _, ok := payload[required]; !ok {
				return nativeCampaignErrorf("invalid_request", 400, "%s is required for create", required)
			}
		}
	case "validate", "start", "status", "pause", "cancel", "resume", "export_manifest":
		if _, ok := payload["campaign_id"]; !ok {
			return nativeCampaignErrorf("invalid_request", 400, "campaign_id is required for %s", action)
		}
	case "list":
		// list is task-scoped by the HTTP/tool path, not by a campaign id.
	}
	return nil
}

func validateNativeCampaignCanonicalValue(value any) error {
	if value == nil {
		return nil
	}
	if number, ok := value.(json.Number); ok {
		text := number.String()
		if text == "" || strings.ContainsAny(text, ".eE+") {
			return nativeCampaignErrorf("invalid_request", 400, "numeric fields must be integers, got %q", text)
		}
		return nil
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Bool, reflect.String:
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if rv.Uint() > math.MaxInt64 {
			return nativeCampaignErrorf("invalid_request", 400, "unsigned integer overflows int64")
		}
		return nil
	case reflect.Float32, reflect.Float64:
		return nativeCampaignErrorf("invalid_request", 400, "floating point values are not canonical integers")
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			if err := validateNativeCampaignCanonicalValue(rv.Index(i).Interface()); err != nil {
				return err
			}
		}
		return nil
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return nativeCampaignErrorf("invalid_request", 400, "canonical object keys must be strings")
		}
		iter := rv.MapRange()
		for iter.Next() {
			if err := validateNativeCampaignCanonicalValue(iter.Value().Interface()); err != nil {
				return err
			}
		}
		return nil
	default:
		return nativeCampaignErrorf("invalid_request", 400, "unsupported canonical value type %T", value)
	}
}

func canonicalNativeCampaignJSON(value any) ([]byte, error) {
	if err := validateNativeCampaignCanonicalValue(value); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, nativeCampaignErrorf("invalid_request", 400, "canonical JSON encode failed: %v", err)
	}
	return raw, nil
}

// CanonicalNativeCampaignRequest returns the canonical request bytes and hash.
// request_id is excluded; static defaults are applied before hashing. The
// state-dependent start/resume attempt default is resolved at claim time and is
// represented as null here so replay identity does not change with budget state.
func CanonicalNativeCampaignRequest(action string, payload map[string]any) ([]byte, string, error) {
	if _, ok := nativeCampaignActions[action]; !ok {
		return nil, "", nativeCampaignErrorf("unknown_action", 400, "unknown campaign action %q", action)
	}
	normalized := make(map[string]any, len(payload)+1)
	normalized["action"] = action
	for key, value := range payload {
		if key == "action" || key == "request_id" {
			continue
		}
		normalized[key] = value
	}
	switch action {
	case "create":
		if _, ok := normalized["argv"]; !ok {
			normalized["argv"] = []any{}
		}
		if _, ok := normalized["input_mode"]; !ok {
			normalized["input_mode"] = "stdin"
		}
		if _, ok := normalized["max_executions"]; !ok {
			normalized["max_executions"] = 1000000
		}
		if _, ok := normalized["max_crashes"]; !ok {
			normalized["max_crashes"] = 4
		}
		if _, ok := normalized["default_attempt_budget_ms"]; !ok {
			if total, ok := nativeCampaignInt64Value(normalized["total_budget_ms"]); ok {
				normalized["default_attempt_budget_ms"] = max(NativeCampaignMinAttemptBudgetMS, min(NativeCampaignDefaultDurationMS, total))
			}
		}
	case "start", "resume":
		if _, ok := normalized["attempt_budget_ms"]; !ok {
			normalized["attempt_budget_ms"] = nil
		}
	case "pause", "cancel":
		if _, ok := normalized["reason"]; !ok {
			normalized["reason"] = ""
		}
	case "status":
		if _, ok := normalized["include_events"]; !ok {
			normalized["include_events"] = false
		}
	case "list":
		if _, ok := normalized["before_id"]; !ok {
			normalized["before_id"] = 0
		}
		if _, ok := normalized["limit"]; !ok {
			normalized["limit"] = 50
		}
	case "export_manifest":
		if _, ok := normalized["max_entries"]; !ok {
			normalized["max_entries"] = 64
		}
	}
	canonical, err := canonicalNativeCampaignJSON(normalized)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canonical)
	return canonical, hex.EncodeToString(sum[:]), nil
}

func nativeCampaignInt64Value(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int8:
		return int64(v), true
	case int16:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case json.Number:
		parsed, err := v.Int64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func nativeCampaignErrorResponse(err *NativeCampaignError) map[string]any {
	if err.Status == 0 {
		err.Status = 500
	}
	details := map[string]any{"code": err.Code, "message": err.Message}
	if err.State != "" {
		details["state"] = err.State
	}
	if err.StateVersion > 0 {
		details["state_version"] = err.StateVersion
	}
	for key, value := range err.Details {
		if _, reserved := details[key]; !reserved {
			details[key] = value
		}
	}
	return map[string]any{"error": details}
}

func nativeCampaignStoredError(status int, body []byte) *NativeCampaignError {
	var payload struct {
		Error struct {
			Code         string         `json:"code"`
			Message      string         `json:"message"`
			State        string         `json:"state"`
			StateVersion int64          `json:"state_version"`
			Details      map[string]any `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.Error.Code != "" {
		return &NativeCampaignError{
			Code: payload.Error.Code, Status: status, Message: payload.Error.Message,
			State: payload.Error.State, StateVersion: payload.Error.StateVersion,
			Details: payload.Error.Details,
		}
	}
	return &NativeCampaignError{Code: "internal", Status: status, Message: "stored campaign response is not an error object"}
}

func responseFlagsFromBody(body []byte) nativeCampaignRequestFlags {
	var payload struct {
		AlreadyQueued    bool `json:"already_queued"`
		AlreadyPaused    bool `json:"already_paused"`
		AlreadyFinalized bool `json:"already_finalized"`
	}
	_ = json.Unmarshal(body, &payload)
	return nativeCampaignRequestFlags{
		alreadyQueued: payload.AlreadyQueued, alreadyPaused: payload.AlreadyPaused,
		alreadyFinalized: payload.AlreadyFinalized,
	}
}

func acquireNativeCampaignRequestLock(ctx context.Context, tx *sql.Tx, taskID int64, requestID string) error {
	wait := nativeCampaignRequestLockWait(ctx)
	deadline := time.Now().Add(wait)
	key := fmt.Sprintf("%d:%s", taskID, requestID)
	for {
		var locked bool
		if err := tx.QueryRowContext(ctx,
			`SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0::bigint))`, key).Scan(&locked); err != nil {
			return err
		}
		if locked {
			return nil
		}
		if !time.Now().Before(deadline) {
			return nativeCampaignErrorf("request_in_progress", 409,
				"another request with this request_id is still in progress")
		}
		sleep := 20 * time.Millisecond
		if remaining := time.Until(deadline); remaining < sleep {
			sleep = remaining
		}
		if sleep < time.Millisecond {
			sleep = time.Millisecond
		}
		timer := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func insertNativeCampaignRequestTx(ctx context.Context, tx *sql.Tx, in NativeCampaignRequestInput) error {
	if in.TaskID <= 0 {
		return nativeCampaignErrorf("invalid_request", 400, "task_id is required")
	}
	if !validNativeCampaignRequestID(in.RequestID) {
		return nativeCampaignErrorf("invalid_request", 400, "request_id must be 1..128 visible ASCII characters")
	}
	if _, ok := nativeCampaignMutationActions[in.Action]; !ok {
		return nativeCampaignErrorf("invalid_request", 400, "action %q cannot be stored as an idempotent mutation", in.Action)
	}
	if err := validateNativeCampaignSHA256(in.RequestHash, "request_hash"); err != nil {
		return nativeCampaignErrorf("invalid_request", 400, "%v", err)
	}
	if in.ResponseStatus < 200 || in.ResponseStatus > 499 {
		return nativeCampaignErrorf("invalid_request", 400, "response_status must be between 200 and 499")
	}
	if len(in.ResponseBody) == 0 || len(in.ResponseBody) > 65536 {
		return nativeCampaignErrorf("internal", 500, "stored response body is outside 1..65536 bytes")
	}
	var body map[string]any
	if err := json.Unmarshal(in.ResponseBody, &body); err != nil {
		return nativeCampaignErrorf("internal", 500, "stored response body is not a JSON object: %v", err)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO native_campaign_requests(
		task_id,campaign_id,request_id,action,request_hash,response_status,response_body)
		VALUES($1,$2,$3,$4,$5,$6,$7)`,
		in.TaskID, in.CampaignID, in.RequestID, in.Action, in.RequestHash,
		in.ResponseStatus, []byte(in.ResponseBody))
	return err
}

func (d *DB) executeNativeCampaignMutation(
	ctx context.Context,
	auth NativeCampaignAuthorizer,
	authReq NativeCampaignAuthorizationRequest,
	action string,
	requestID string,
	payload map[string]any,
	fn nativeCampaignMutationFunc,
) (*NativeCampaignCommandResponse, error) {
	if _, ok := nativeCampaignMutationActions[action]; !ok {
		return nil, nativeCampaignErrorf("unknown_action", 400, "unknown mutation action %q", action)
	}
	if !validNativeCampaignRequestID(requestID) {
		return nil, nativeCampaignErrorf("invalid_request", 400, "request_id must be 1..128 visible ASCII characters")
	}
	if auth == nil {
		return nil, nativeCampaignErrorf("authorization_revoked", 403, "an explicit campaign authorizer is required")
	}
	_, requestHash, err := CanonicalNativeCampaignRequest(action, payload)
	if err != nil {
		return nil, err
	}
	authReq.Action = action
	if err := auth(ctx, authReq); err != nil {
		if NativeCampaignErrorCode(err) == "archive_restore_not_executable" {
			return nil, err
		}
		return nil, &NativeCampaignError{
			Code: "authorization_revoked", Status: 403,
			Message: "campaign authorization denied",
		}
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nativeCampaignErrorf("internal", 500, "begin campaign transaction: %v", err)
	}
	defer tx.Rollback()
	purpose := nativeCampaignNewWrite
	if action == "pause" || action == "cancel" {
		purpose = nativeCampaignOwnedSettlement
	}
	if err := admitNativeCampaignWriteTx(ctx, tx, authReq.TaskID, purpose); err != nil {
		return nil, err
	}
	if action == "start" || action == "resume" {
		if err := rejectNativeCampaignArchiveRestoredTx(ctx, tx, authReq.TaskID, authReq.CampaignID); err != nil {
			return nil, err
		}
	}

	if err := acquireNativeCampaignRequestLock(ctx, tx, authReq.TaskID, requestID); err != nil {
		return nil, err
	}

	var existingHash string
	var existingStatus int
	var existingBody []byte
	err = tx.QueryRowContext(ctx, `SELECT request_hash,response_status,response_body
		FROM native_campaign_requests WHERE task_id=$1 AND request_id=$2`,
		authReq.TaskID, requestID).Scan(&existingHash, &existingStatus, &existingBody)
	if err == nil {
		if existingHash != requestHash {
			return nil, nativeCampaignErrorf("idempotency_conflict", 409,
				"request_id %q was already used with a different request hash", requestID)
		}
		if err := tx.Commit(); err != nil {
			return nil, nativeCampaignErrorf("internal", 500, "commit replay transaction: %v", err)
		}
		flags := responseFlagsFromBody(existingBody)
		resp := &NativeCampaignCommandResponse{
			Status: existingStatus, Body: existingBody, Replayed: true,
			AlreadyQueued: flags.alreadyQueued, AlreadyPaused: flags.alreadyPaused,
			AlreadyFinalized: flags.alreadyFinalized,
		}
		if existingStatus >= 400 {
			return resp, nativeCampaignStoredError(existingStatus, existingBody)
		}
		return resp, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignErrorf("internal", 500, "read idempotency row: %v", err)
	}

	status, bodyValue, flags, opErr := fn(ctx, tx)
	if opErr != nil {
		var campaignErr *NativeCampaignError
		if errors.As(opErr, &campaignErr) && campaignErr.Status > 0 && campaignErr.Status < 500 {
			body, marshalErr := json.Marshal(nativeCampaignErrorResponse(campaignErr))
			if marshalErr != nil {
				return nil, nativeCampaignErrorf("internal", 500, "encode campaign error: %v", marshalErr)
			}
			var taskExists bool
			if err := tx.QueryRowContext(ctx,
				`SELECT EXISTS(SELECT 1 FROM tasks WHERE id=$1 AND deleted_at IS NULL)`,
				authReq.TaskID).Scan(&taskExists); err != nil {
				return nil, nativeCampaignErrorf("internal", 500, "check task before caching 4xx: %v", err)
			}
			if !taskExists {
				// A missing task cannot own a request row (and its FK would turn
				// a correct 404 into a 500). Do not cache this response.
				return nil, campaignErr
			}
			campaignID := nativeCampaignCampaignID(authReq.CampaignID)
			if campaignErr.Status == 404 {
				// The 404 may be a nonexistent or cross-task campaign. Linking
				// that id would violate the composite (campaign_id, task_id) FK,
				// so a deterministic 404 is stored with a NULL association.
				campaignID = nil
			}
			if err := insertNativeCampaignRequestTx(ctx, tx, NativeCampaignRequestInput{
				TaskID: authReq.TaskID, CampaignID: campaignID,
				RequestID: requestID, Action: action, RequestHash: requestHash,
				ResponseStatus: campaignErr.Status, ResponseBody: body,
			}); err != nil {
				return nil, nativeCampaignErrorf("internal", 500, "store deterministic campaign error: %v", err)
			}
			if err := tx.Commit(); err != nil {
				return nil, nativeCampaignErrorf("internal", 500, "commit deterministic campaign error: %v", err)
			}
			resp := &NativeCampaignCommandResponse{Status: campaignErr.Status, Body: body}
			return resp, campaignErr
		}
		return nil, opErr
	}
	if status < 200 || status >= 500 {
		return nil, nativeCampaignErrorf("internal", 500, "mutation returned invalid status %d", status)
	}
	if err := nativeCampaignFault(ctx, action); err != nil {
		return nil, nativeCampaignErrorf("internal", 500, "injected %s commit failure: %v", action, err)
	}
	body, err := json.Marshal(bodyValue)
	if err != nil {
		return nil, nativeCampaignErrorf("internal", 500, "encode campaign response: %v", err)
	}
	if err := insertNativeCampaignRequestTx(ctx, tx, NativeCampaignRequestInput{
		TaskID: authReq.TaskID, CampaignID: nativeCampaignCampaignID(authReq.CampaignID),
		RequestID: requestID, Action: action, RequestHash: requestHash,
		ResponseStatus: status, ResponseBody: body,
	}); err != nil {
		return nil, nativeCampaignErrorf("internal", 500, "store campaign response: %v", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, nativeCampaignErrorf("internal", 500, "commit campaign mutation: %v", err)
	}
	return &NativeCampaignCommandResponse{
		Status: status, Body: body,
		AlreadyQueued: flags.alreadyQueued, AlreadyPaused: flags.alreadyPaused,
		AlreadyFinalized: flags.alreadyFinalized,
	}, nil
}

func nativeCampaignCampaignID(id int64) *int64 {
	if id <= 0 {
		return nil
	}
	return &id
}

// CanonicalNativeCampaignSpec validates and canonicalizes an immutable campaign
// spec, returning its byte form and sha256.
func CanonicalNativeCampaignSpec(raw json.RawMessage) ([]byte, string, error) {
	canonical, err := normalizeNativeCampaignJSONObject(raw, NativeCampaignSpecBytes, "spec")
	if err != nil {
		return nil, "", nativeCampaignErrorf("invalid_request", 400, "%v", err)
	}
	sum := sha256.Sum256(canonical)
	return canonical, hex.EncodeToString(sum[:]), nil
}

// normalizeNativeCampaignRequestID is a tiny shared helper kept here so tests
// can assert the exact visible-ASCII rule without reimplementing it.
func normalizeNativeCampaignRequestID(requestID string) error {
	if !validNativeCampaignRequestID(requestID) {
		return nativeCampaignErrorf("invalid_request", 400, "request_id must be 1..128 visible ASCII characters")
	}
	return nil
}
