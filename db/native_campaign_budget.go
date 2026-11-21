package db

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// Native Campaign v1 (T3) budget model.
//
// The v1 draft originally described profile/policy max_duration as an AFL
// observation window sitting next to a separate startup overhead. The existing
// campaign runner does not behave that way: its duration deadline starts before
// validation/startup and covers staging, help/tool probes and target work. A
// profile/policy cap is therefore an authorized execution-window cap, not an
// extra window that can be added to overhead.
//
// This file exposes two distinct numbers:
//   - ExecutionWindowMS: wall-clock budget for all authorized startup/probe/work
//     inside profile/policy limits. It is never extended by cleanup reserve.
//   - ReservedMS: the total attempt envelope. It can be larger than the
//     execution window (fixed overhead plus bounded cleanup reserve), but a
//     larger envelope must never enlarge the execution window.
//
// These are pure calculations. They do not claim the existing runner already
// consumes ExecutionWindowMS; T4 owns that runner/deadline implementation.

const (
	NativeCampaignMinAttemptBudgetMS   int64 = 6000
	NativeCampaignMaxAttemptBudgetMS   int64 = 900000
	NativeCampaignOverheadReserveMS    int64 = 5000
	NativeCampaignMinExecutionMS       int64 = 1000
	NativeCampaignMaxTotalBudgetMS     int64 = 86400000
	NativeCampaignCleanupHardTimeoutMS int64 = 60000
	NativeCampaignSettlementSlackMS    int64 = 1000
	NativeCampaignSettlementStepMS     int64 = 100
	NativeCampaignDefaultDurationMS    int64 = 60000
	// NativeCampaignCompatDefaultAttemptBudgetMS is the fixed compatibility
	// default for legacy immutable specs that predate
	// default_attempt_budget_ms. It is still bounded by the remaining campaign
	// budget at claim time.
	NativeCampaignCompatDefaultAttemptBudgetMS int64 = 60000
	NativeCampaignDefaultLeaseMS               int64 = 30000
	NativeCampaignMinLeaseMS                   int64 = 1000
	NativeCampaignMaxLeaseMS                   int64 = 120000
)

// NativeCampaignBudgetInput is the pure claim-time budget request.
//
// RequestedBudgetMS == 0 means "use DefaultBudgetMS"; DefaultBudgetMS == 0
// means the v1 default min(60000, remaining). Profile/Policy values == 0 use
// the documented 60000 default. Explicit non-zero values are validated, never
// silently raised or lowered. The campaign claim path resolves the durable
// default from the immutable spec before calling this pure function and does
// not pass a caller/scheduler default.
type NativeCampaignBudgetInput struct {
	TotalBudgetMS        int64
	ChargedBudgetMS      int64
	RequestedBudgetMS    int64
	DefaultBudgetMS      int64
	ProfileMaxDurationMS int64
	PolicyMaxDurationMS  int64
}

// NativeCampaignBudgetPlan is the claim-time reservation plan.
type NativeCampaignBudgetPlan struct {
	TotalBudgetMS        int64 `json:"total_budget_ms"`
	ChargedBudgetMS      int64 `json:"charged_budget_ms"`
	RemainingBudgetMS    int64 `json:"remaining_budget_ms"`
	ReservedBudgetMS     int64 `json:"reserved_budget_ms"`
	ExecutionWindowMS    int64 `json:"execution_window_ms"`
	OverheadReserveMS    int64 `json:"overhead_reserve_ms"`
	CleanupReserveMS     int64 `json:"cleanup_reserve_ms"`
	CleanupHardTimeoutMS int64 `json:"cleanup_hard_timeout_ms"`
	ProfileMaxDurationMS int64 `json:"profile_max_duration_ms"`
	PolicyMaxDurationMS  int64 `json:"policy_max_duration_ms"`
}

// NativeCampaignDeadline is the explicit T4 deadline contract derived from a
// plan. Times are absolute so a runner restart cannot re-base the window.
type NativeCampaignDeadline struct {
	StartedAt            time.Time `json:"started_at"`
	ExecutionDeadline    time.Time `json:"execution_deadline"`
	EnvelopeDeadline     time.Time `json:"envelope_deadline"`
	ExecutionWindowMS    int64     `json:"execution_window_ms"`
	ReservedBudgetMS     int64     `json:"reserved_budget_ms"`
	CleanupHardTimeoutMS int64     `json:"cleanup_hard_timeout_ms"`
	CleanupReserveMS     int64     `json:"cleanup_reserve_ms"`
}

// NativeCampaignSettlementInput is the pure finalize accounting input. Elapsed
// values must come from the trusted server monotonic clock, not from the
// runner's self-reported wall clock.
type NativeCampaignSettlementInput struct {
	ReservedBudgetMS  int64
	ElapsedMS         int64
	CleanupElapsedMS  int64
	CleanupReserveMS  int64
	CampaignChargedMS int64
	CampaignTotalMS   int64
	FinalLost         bool
	CleanupUnknown    bool
}

// NativeCampaignSettlement is the conservative ledger outcome.
type NativeCampaignSettlement struct {
	ReservedBudgetMS           int64 `json:"reserved_budget_ms"`
	LedgerMS                   int64 `json:"ledger_ms"`
	CampaignChargedMS          int64 `json:"campaign_charged_ms"`
	ActualElapsedMS            int64 `json:"actual_elapsed_ms"`
	CleanupOverrunMS           int64 `json:"cleanup_overrun_ms"`
	CleanupHardTimeoutExceeded bool  `json:"cleanup_hard_timeout_exceeded"`
	BudgetOverrun              bool  `json:"budget_overrun"`
	LostOrUnknown              bool  `json:"lost_or_unknown"`
}

// ParseNativeCampaignBudgetMS parses a JSON integer budget value. It rejects
// strings, floats, exponents and values outside int64 instead of coercing them.
func ParseNativeCampaignBudgetMS(raw []byte) (int64, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return 0, nativeCampaignErrorf("invalid_request", 400, "budget must be a JSON integer: %v", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return 0, nativeCampaignErrorf("invalid_request", 400, "budget has trailing JSON data")
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, nativeCampaignErrorf("invalid_request", 400, "budget must be a JSON integer")
	}
	text := number.String()
	if strings.ContainsAny(text, ".eE+") {
		return 0, nativeCampaignErrorf("invalid_request", 400, "budget must be an integer, not a float or exponent")
	}
	parsed, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, nativeCampaignErrorf("invalid_request", 400, "budget is outside int64")
	}
	return parsed, nil
}

// nativeCampaignSpecDefaultAttemptBudgetMS reads the immutable spec's
// default_attempt_budget_ms. The field is optional for legacy specs, but when
// it is present it must be a literal JSON integer in 6000..900000. null,
// strings, floats, negatives, booleans and int64 overflow are never accepted as
// a default.
func nativeCampaignSpecDefaultAttemptBudgetMS(spec json.RawMessage) (int64, bool, error) {
	if len(spec) == 0 {
		return 0, false, nativeCampaignErrorf("invalid_request", 400, "spec is required")
	}
	dec := json.NewDecoder(bytes.NewReader(spec))
	var object map[string]json.RawMessage
	if err := dec.Decode(&object); err != nil {
		return 0, false, nativeCampaignErrorf("invalid_request", 400, "spec must be a JSON object: %v", err)
	}
	if object == nil {
		return 0, false, nativeCampaignErrorf("invalid_request", 400, "spec must be a JSON object")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return 0, false, nativeCampaignErrorf("invalid_request", 400, "spec has trailing JSON data")
	}
	raw, ok := object["default_attempt_budget_ms"]
	if !ok {
		return 0, false, nil
	}
	budget, err := ParseNativeCampaignBudgetMS(raw)
	if err != nil {
		return 0, true, err
	}
	if budget < NativeCampaignMinAttemptBudgetMS || budget > NativeCampaignMaxAttemptBudgetMS {
		return 0, true, nativeCampaignErrorf("invalid_request", 400,
			"spec default_attempt_budget_ms must be between %d and %d, got %d",
			NativeCampaignMinAttemptBudgetMS, NativeCampaignMaxAttemptBudgetMS, budget)
	}
	return budget, true, nil
}

// nativeCampaignDefaultAttemptBudgetCapMS is the single source of the default
// attempt authorization. A persisted spec field wins (min with remaining); a
// legacy spec without the field keeps the fixed 60000ms compatibility default
// (also min with remaining). Caller-side defaults are deliberately not an
// input here.
func nativeCampaignDefaultAttemptBudgetCapMS(spec json.RawMessage, remaining int64) (int64, error) {
	if remaining < NativeCampaignMinAttemptBudgetMS {
		return 0, nativeCampaignErrorf("budget_exhausted", 409,
			"remaining budget %dms is below the %dms minimum", remaining, NativeCampaignMinAttemptBudgetMS)
	}
	budget, present, err := nativeCampaignSpecDefaultAttemptBudgetMS(spec)
	if err != nil {
		return 0, err
	}
	if !present {
		budget = NativeCampaignCompatDefaultAttemptBudgetMS
	}
	return min(budget, remaining), nil
}

// nativeCampaignValidateDefaultAttemptBudget validates the durable default when
// start/resume omits an explicit attempt_budget_ms, so a bad immutable spec is
// rejected before any state or event write.
func nativeCampaignValidateDefaultAttemptBudget(spec json.RawMessage, remaining int64) error {
	_, err := nativeCampaignDefaultAttemptBudgetCapMS(spec, remaining)
	return err
}

// PlanNativeCampaignBudget validates the remaining budget and returns the
// reservation plus the authorized execution window. It rejects explicit values
// below the 6000ms minimum, above 900000ms, above the remaining budget, and
// integer overflow. It never raises an explicit user request.
func PlanNativeCampaignBudget(in NativeCampaignBudgetInput) (*NativeCampaignBudgetPlan, error) {
	if in.TotalBudgetMS < NativeCampaignMinAttemptBudgetMS || in.TotalBudgetMS > NativeCampaignMaxTotalBudgetMS {
		return nil, nativeCampaignErrorf("invalid_request", 400,
			"total_budget_ms must be between %d and %d", NativeCampaignMinAttemptBudgetMS, NativeCampaignMaxTotalBudgetMS)
	}
	if in.ChargedBudgetMS < 0 || in.ChargedBudgetMS > in.TotalBudgetMS {
		return nil, nativeCampaignErrorf("invalid_request", 400, "charged_budget_ms is outside 0..total_budget_ms")
	}
	remaining := in.TotalBudgetMS - in.ChargedBudgetMS
	if remaining < NativeCampaignMinAttemptBudgetMS {
		return nil, nativeCampaignErrorf("budget_exhausted", 409,
			"remaining budget %dms is below the %dms minimum", remaining, NativeCampaignMinAttemptBudgetMS)
	}

	profileMax := in.ProfileMaxDurationMS
	if profileMax == 0 {
		profileMax = NativeCampaignDefaultDurationMS
	}
	policyMax := in.PolicyMaxDurationMS
	if policyMax == 0 {
		policyMax = NativeCampaignDefaultDurationMS
	}
	if profileMax < 0 || policyMax < 0 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "profile/policy max_duration_ms must be non-negative")
	}

	maxAllowed := min(NativeCampaignMaxAttemptBudgetMS, remaining)
	requested := in.RequestedBudgetMS
	if requested == 0 {
		requested = in.DefaultBudgetMS
		if requested == 0 {
			requested = min(NativeCampaignDefaultDurationMS, remaining)
		}
	} else if requested < NativeCampaignMinAttemptBudgetMS {
		return nil, nativeCampaignErrorf("invalid_request", 400,
			"attempt_budget_ms %d is below the %dms minimum", requested, NativeCampaignMinAttemptBudgetMS)
	}
	if requested > NativeCampaignMaxAttemptBudgetMS {
		return nil, nativeCampaignErrorf("invalid_request", 400,
			"attempt_budget_ms %d exceeds the %dms attempt maximum", requested, NativeCampaignMaxAttemptBudgetMS)
	}
	if requested < NativeCampaignMinAttemptBudgetMS {
		return nil, nativeCampaignErrorf("budget_exhausted", 409,
			"attempt_budget_ms %d is below the %dms minimum", requested, NativeCampaignMinAttemptBudgetMS)
	}
	if requested > maxAllowed {
		return nil, nativeCampaignErrorf("budget_exhausted", 409,
			"attempt_budget_ms %d exceeds remaining/min(attempt max) %dms", requested, maxAllowed)
	}

	// Keep the fixed overhead reserve inside the envelope. The execution window
	// covers startup/probe/work and is capped by profile/policy; the cleanup
	// reserve is the non-execution remainder and is hard-capped at 60s.
	available := requested - NativeCampaignOverheadReserveMS
	if available < NativeCampaignMinExecutionMS {
		return nil, nativeCampaignErrorf("environment_incompatible", 409,
			"attempt envelope %dms leaves no %dms execution window after the %dms overhead reserve",
			requested, NativeCampaignMinExecutionMS, NativeCampaignOverheadReserveMS)
	}
	execution := min(profileMax, policyMax, available)
	if execution < NativeCampaignMinExecutionMS {
		return nil, nativeCampaignErrorf("environment_incompatible", 409,
			"profile/policy execution window %dms is below the %dms minimum", execution, NativeCampaignMinExecutionMS)
	}
	cleanupReserve := min(NativeCampaignCleanupHardTimeoutMS, requested-execution)
	if cleanupReserve < 0 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "negative cleanup reserve")
	}
	return &NativeCampaignBudgetPlan{
		TotalBudgetMS:        in.TotalBudgetMS,
		ChargedBudgetMS:      in.ChargedBudgetMS,
		RemainingBudgetMS:    remaining,
		ReservedBudgetMS:     requested,
		ExecutionWindowMS:    execution,
		OverheadReserveMS:    NativeCampaignOverheadReserveMS,
		CleanupReserveMS:     cleanupReserve,
		CleanupHardTimeoutMS: NativeCampaignCleanupHardTimeoutMS,
		ProfileMaxDurationMS: profileMax,
		PolicyMaxDurationMS:  policyMax,
	}, nil
}

// Deadlines returns the absolute T4 contract for a plan. The execution deadline
// is the only deadline that may stop target work; cleanup has a separate 60s
// hard deadline measured from the stop request.
func (p NativeCampaignBudgetPlan) Deadlines(started time.Time) NativeCampaignDeadline {
	return NativeCampaignDeadline{
		StartedAt:            started,
		ExecutionDeadline:    started.Add(time.Duration(p.ExecutionWindowMS) * time.Millisecond),
		EnvelopeDeadline:     started.Add(time.Duration(p.ReservedBudgetMS) * time.Millisecond),
		ExecutionWindowMS:    p.ExecutionWindowMS,
		ReservedBudgetMS:     p.ReservedBudgetMS,
		CleanupHardTimeoutMS: NativeCampaignCleanupHardTimeoutMS,
		CleanupReserveMS:     p.CleanupReserveMS,
	}
}

// CleanupDeadline is the independent 60s hard cap on safety cleanup.
func (p NativeCampaignBudgetPlan) CleanupDeadline(stopRequested time.Time) time.Time {
	return stopRequested.Add(time.Duration(NativeCampaignCleanupHardTimeoutMS) * time.Millisecond)
}

// nativeCampaignCeil100MS rounds a non-negative millisecond value up to 100ms
// with explicit overflow protection.
func nativeCampaignCeil100MS(value int64) (int64, error) {
	if value < 0 {
		return 0, nativeCampaignErrorf("invalid_request", 400, "elapsed must be non-negative")
	}
	if value > math.MaxInt64-(NativeCampaignSettlementStepMS-1) {
		return 0, nativeCampaignErrorf("invalid_request", 400, "elapsed overflows 100ms rounding")
	}
	remainder := value % NativeCampaignSettlementStepMS
	if remainder == 0 {
		return value, nil
	}
	return value + (NativeCampaignSettlementStepMS - remainder), nil
}

// SettleNativeCampaignBudget implements spec 5.3 as a pure calculation.
//
// A valid final uses min(reserved, ceil100(elapsed+1000)). A lost final or
// unknown cleanup settles the whole reservation. Running past the reservation
// records overrun and also settles the whole reservation. charged+delta above
// total is an invariant error; this function never clamps the ledger.
func SettleNativeCampaignBudget(in NativeCampaignSettlementInput) (*NativeCampaignSettlement, error) {
	if in.ReservedBudgetMS < NativeCampaignMinAttemptBudgetMS || in.ReservedBudgetMS > NativeCampaignMaxAttemptBudgetMS {
		return nil, nativeCampaignErrorf("invalid_request", 400,
			"reserved_budget_ms must be between %d and %d", NativeCampaignMinAttemptBudgetMS, NativeCampaignMaxAttemptBudgetMS)
	}
	if in.CampaignTotalMS < NativeCampaignMinAttemptBudgetMS || in.CampaignTotalMS > NativeCampaignMaxTotalBudgetMS {
		return nil, nativeCampaignErrorf("invalid_request", 400, "campaign total budget is invalid")
	}
	if in.CampaignChargedMS < 0 || in.CampaignChargedMS > in.CampaignTotalMS {
		return nil, nativeCampaignErrorf("invalid_request", 400, "campaign charged budget is outside 0..total")
	}
	if in.ElapsedMS < 0 || in.CleanupElapsedMS < 0 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "elapsed values must be non-negative")
	}
	cleanupReserve := in.CleanupReserveMS
	if cleanupReserve == 0 {
		cleanupReserve = NativeCampaignOverheadReserveMS
	}
	if cleanupReserve < 0 || cleanupReserve > NativeCampaignCleanupHardTimeoutMS {
		return nil, nativeCampaignErrorf("invalid_request", 400,
			"cleanup_reserve_ms must be between 0 and %d", NativeCampaignCleanupHardTimeoutMS)
	}

	lost := in.FinalLost || in.CleanupUnknown
	ledger := in.ReservedBudgetMS
	overrun := in.ElapsedMS > in.ReservedBudgetMS
	if !lost && !overrun {
		if in.ElapsedMS > math.MaxInt64-NativeCampaignSettlementSlackMS {
			return nil, nativeCampaignErrorf("invalid_request", 400, "elapsed overflows the settlement slack")
		}
		rounded, err := nativeCampaignCeil100MS(in.ElapsedMS + NativeCampaignSettlementSlackMS)
		if err != nil {
			return nil, err
		}
		ledger = min(in.ReservedBudgetMS, rounded)
	}
	if ledger < 0 || ledger > in.ReservedBudgetMS {
		return nil, nativeCampaignErrorf("internal", 500, "settlement ledger is outside 0..reserved")
	}

	cleanupOverrun := int64(0)
	if in.CleanupElapsedMS > cleanupReserve {
		cleanupOverrun = in.CleanupElapsedMS - cleanupReserve
	}
	cleanupHardExceeded := in.CleanupElapsedMS > NativeCampaignCleanupHardTimeoutMS

	if in.CampaignChargedMS > math.MaxInt64-ledger {
		return nil, nativeCampaignErrorf("budget_invariant", 500, "campaign charged budget overflows int64")
	}
	newCharged := in.CampaignChargedMS + ledger
	if newCharged > in.CampaignTotalMS {
		return nil, nativeCampaignErrorf("budget_invariant", 500,
			"campaign charged %d + ledger %d exceeds total %d; refusing to clamp",
			in.CampaignChargedMS, ledger, in.CampaignTotalMS)
	}

	return &NativeCampaignSettlement{
		ReservedBudgetMS:           in.ReservedBudgetMS,
		LedgerMS:                   ledger,
		CampaignChargedMS:          newCharged,
		ActualElapsedMS:            in.ElapsedMS,
		CleanupOverrunMS:           cleanupOverrun,
		CleanupHardTimeoutExceeded: cleanupHardExceeded,
		BudgetOverrun:              overrun,
		LostOrUnknown:              lost,
	}, nil
}

// ValidateNativeCampaignLeaseMS normalizes/validates a lease duration.
func ValidateNativeCampaignLeaseMS(leaseMS int64) (int64, error) {
	if leaseMS == 0 {
		return NativeCampaignDefaultLeaseMS, nil
	}
	if leaseMS < NativeCampaignMinLeaseMS || leaseMS > NativeCampaignMaxLeaseMS {
		return 0, nativeCampaignErrorf("invalid_request", 400,
			"lease_ms must be between %d and %d", NativeCampaignMinLeaseMS, NativeCampaignMaxLeaseMS)
	}
	return leaseMS, nil
}
