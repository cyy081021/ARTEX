package db

import (
	"math"
	"testing"
	"time"
)

func requireNativeCampaignCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, got nil", code)
	}
	if got := NativeCampaignErrorCode(err); got != code {
		t.Fatalf("error code=%q want %q (err=%v)", got, code, err)
	}
}

func TestNativeCampaignBudgetPlanBoundaries(t *testing.T) {
	t.Run("minimum_and_default", func(t *testing.T) {
		plan, err := PlanNativeCampaignBudget(NativeCampaignBudgetInput{TotalBudgetMS: 6000})
		if err != nil {
			t.Fatal(err)
		}
		if plan.ReservedBudgetMS != 6000 || plan.ExecutionWindowMS != 1000 ||
			plan.RemainingBudgetMS != 6000 || plan.CleanupReserveMS != 5000 {
			t.Fatalf("minimum plan=%+v", plan)
		}
		plan, err = PlanNativeCampaignBudget(NativeCampaignBudgetInput{TotalBudgetMS: 600000})
		if err != nil {
			t.Fatal(err)
		}
		if plan.ReservedBudgetMS != 60000 || plan.ExecutionWindowMS != 55000 {
			t.Fatalf("default plan=%+v", plan)
		}
	})
	t.Run("explicit_below_minimum_is_rejected_not_raised", func(t *testing.T) {
		budget := int64(5999)
		_, err := PlanNativeCampaignBudget(NativeCampaignBudgetInput{
			TotalBudgetMS: 600000, RequestedBudgetMS: budget,
		})
		requireNativeCampaignCode(t, err, "invalid_request")
	})
	t.Run("explicit_zero_is_omitted", func(t *testing.T) {
		_, err := PlanNativeCampaignBudget(NativeCampaignBudgetInput{
			TotalBudgetMS: 600000, RequestedBudgetMS: 0, DefaultBudgetMS: 5000,
		})
		requireNativeCampaignCode(t, err, "budget_exhausted")
	})
	t.Run("overflow_and_above_attempt_max_are_rejected", func(t *testing.T) {
		for _, requested := range []int64{900001, math.MaxInt64} {
			_, err := PlanNativeCampaignBudget(NativeCampaignBudgetInput{
				TotalBudgetMS: 86400000, RequestedBudgetMS: requested,
			})
			requireNativeCampaignCode(t, err, "invalid_request")
		}
	})
	t.Run("remaining_below_minimum", func(t *testing.T) {
		_, err := PlanNativeCampaignBudget(NativeCampaignBudgetInput{
			TotalBudgetMS: 6000, ChargedBudgetMS: 1000,
		})
		requireNativeCampaignCode(t, err, "budget_exhausted")
	})
	t.Run("requested_above_remaining", func(t *testing.T) {
		_, err := PlanNativeCampaignBudget(NativeCampaignBudgetInput{
			TotalBudgetMS: 10000, RequestedBudgetMS: 11000,
		})
		requireNativeCampaignCode(t, err, "budget_exhausted")
	})
	t.Run("bad_total_and_charged", func(t *testing.T) {
		for _, in := range []NativeCampaignBudgetInput{
			{TotalBudgetMS: 5999},
			{TotalBudgetMS: 86400001},
			{TotalBudgetMS: 600000, ChargedBudgetMS: -1},
			{TotalBudgetMS: 600000, ChargedBudgetMS: 600001},
		} {
			_, err := PlanNativeCampaignBudget(in)
			requireNativeCampaignCode(t, err, "invalid_request")
		}
	})
	t.Run("execution_window_below_minimum", func(t *testing.T) {
		_, err := PlanNativeCampaignBudget(NativeCampaignBudgetInput{
			TotalBudgetMS: 600000, ProfileMaxDurationMS: 500, PolicyMaxDurationMS: 60000,
		})
		requireNativeCampaignCode(t, err, "environment_incompatible")
	})
}

func TestNativeCampaignBudgetExecutionWindowIsNotEnlarged(t *testing.T) {
	base := NativeCampaignBudgetInput{
		TotalBudgetMS: 600000, RequestedBudgetMS: 60000,
		ProfileMaxDurationMS: 30000, PolicyMaxDurationMS: 20000,
	}
	plan, err := PlanNativeCampaignBudget(base)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ExecutionWindowMS != 20000 {
		t.Fatalf("execution window=%d want 20000 (min(profile,policy), no additive AFL window)", plan.ExecutionWindowMS)
	}
	enlarged := base
	enlarged.RequestedBudgetMS = 120000
	plan2, err := PlanNativeCampaignBudget(enlarged)
	if err != nil {
		t.Fatal(err)
	}
	if plan2.ExecutionWindowMS != plan.ExecutionWindowMS {
		t.Fatalf("larger reserved envelope changed execution window: %d -> %d", plan.ExecutionWindowMS, plan2.ExecutionWindowMS)
	}
	if plan2.CleanupReserveMS <= plan.CleanupReserveMS {
		t.Fatalf("larger envelope should only increase non-execution reserve: %+v vs %+v", plan, plan2)
	}

	started := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	deadlines := plan2.Deadlines(started)
	if want := started.Add(20 * time.Second); !deadlines.ExecutionDeadline.Equal(want) {
		t.Fatalf("execution deadline=%v want %v", deadlines.ExecutionDeadline, want)
	}
	if want := started.Add(120 * time.Second); !deadlines.EnvelopeDeadline.Equal(want) {
		t.Fatalf("envelope deadline=%v want %v", deadlines.EnvelopeDeadline, want)
	}
	if deadlines.ExecutionDeadline.After(deadlines.EnvelopeDeadline) {
		t.Fatal("execution deadline must not exceed the envelope deadline")
	}
	stop := started.Add(30 * time.Second)
	if want := stop.Add(60 * time.Second); !plan2.CleanupDeadline(stop).Equal(want) {
		t.Fatalf("cleanup deadline=%v want %v (independent 60s hard cap)", plan2.CleanupDeadline(stop), want)
	}
	if plan2.CleanupHardTimeoutMS != 60000 {
		t.Fatalf("cleanup hard timeout=%d", plan2.CleanupHardTimeoutMS)
	}
}

func TestNativeCampaignBudgetParse(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int64
		code string
	}{
		{`6000`, 6000, ""},
		{`900000`, 900000, ""},
		{`6000.0`, 0, "invalid_request"},
		{`1e3`, 0, "invalid_request"},
		{`"6000"`, 0, "invalid_request"},
		{`null`, 0, "invalid_request"},
		{`9223372036854775808`, 0, "invalid_request"},
		{`6000 1`, 0, "invalid_request"},
	} {
		got, err := ParseNativeCampaignBudgetMS([]byte(tc.raw))
		if tc.code == "" {
			if err != nil || got != tc.want {
				t.Fatalf("parse %s = %d,%v want %d", tc.raw, got, err, tc.want)
			}
		} else if code := NativeCampaignErrorCode(err); code != tc.code {
			t.Fatalf("parse %s code=%q want %q err=%v", tc.raw, code, tc.code, err)
		}
	}
}

func TestNativeCampaignBudgetSettlement(t *testing.T) {
	t.Run("valid_final_rounds_up_with_slack", func(t *testing.T) {
		out, err := SettleNativeCampaignBudget(NativeCampaignSettlementInput{
			ReservedBudgetMS: 60000, ElapsedMS: 1001, CampaignTotalMS: 600000,
		})
		if err != nil {
			t.Fatal(err)
		}
		if out.LedgerMS != 2100 || out.CampaignChargedMS != 2100 || out.BudgetOverrun {
			t.Fatalf("settlement=%+v", out)
		}
		out, err = SettleNativeCampaignBudget(NativeCampaignSettlementInput{
			ReservedBudgetMS: 60000, ElapsedMS: 0, CampaignTotalMS: 600000,
		})
		if err != nil || out.LedgerMS != 1000 {
			t.Fatalf("zero elapsed settlement=%+v err=%v", out, err)
		}
	})
	t.Run("lost_and_unknown_settle_full_reservation", func(t *testing.T) {
		for _, in := range []NativeCampaignSettlementInput{
			{ReservedBudgetMS: 60000, ElapsedMS: 0, CampaignTotalMS: 600000, FinalLost: true},
			{ReservedBudgetMS: 60000, ElapsedMS: 0, CampaignTotalMS: 600000, CleanupUnknown: true},
		} {
			out, err := SettleNativeCampaignBudget(in)
			if err != nil {
				t.Fatal(err)
			}
			if out.LedgerMS != 60000 || !out.LostOrUnknown {
				t.Fatalf("lost/unknown settlement=%+v", out)
			}
		}
	})
	t.Run("elapsed_over_reservation_records_overrun", func(t *testing.T) {
		out, err := SettleNativeCampaignBudget(NativeCampaignSettlementInput{
			ReservedBudgetMS: 6000, ElapsedMS: 6001, CampaignTotalMS: 600000,
		})
		if err != nil {
			t.Fatal(err)
		}
		if out.LedgerMS != 6000 || !out.BudgetOverrun {
			t.Fatalf("overrun settlement=%+v", out)
		}
	})
	t.Run("cleanup_overrun_and_hard_timeout_are_recorded", func(t *testing.T) {
		out, err := SettleNativeCampaignBudget(NativeCampaignSettlementInput{
			ReservedBudgetMS: 60000, ElapsedMS: 5000, CleanupElapsedMS: 65000,
			CleanupReserveMS: 5000, CampaignTotalMS: 600000,
		})
		if err != nil {
			t.Fatal(err)
		}
		if out.CleanupOverrunMS != 60000 || !out.CleanupHardTimeoutExceeded {
			t.Fatalf("cleanup overrun=%+v", out)
		}
	})
	t.Run("charged_plus_delta_above_total_is_an_error_not_a_clamp", func(t *testing.T) {
		_, err := SettleNativeCampaignBudget(NativeCampaignSettlementInput{
			ReservedBudgetMS: 6000, ElapsedMS: 0, CampaignTotalMS: 60000, CampaignChargedMS: 59500,
		})
		requireNativeCampaignCode(t, err, "budget_invariant")
	})
	t.Run("overflow_protection", func(t *testing.T) {
		if _, err := nativeCampaignCeil100MS(math.MaxInt64); err == nil {
			t.Fatal("ceil100(math.MaxInt64) should report overflow")
		}
		out, err := SettleNativeCampaignBudget(NativeCampaignSettlementInput{
			ReservedBudgetMS: 900000, ElapsedMS: math.MaxInt64, CampaignTotalMS: 86400000,
		})
		if err != nil {
			t.Fatal(err)
		}
		if out.LedgerMS != 900000 || !out.BudgetOverrun {
			t.Fatalf("huge elapsed settlement=%+v", out)
		}
	})
	t.Run("invalid_inputs", func(t *testing.T) {
		cases := []NativeCampaignSettlementInput{
			{ReservedBudgetMS: 5999, CampaignTotalMS: 600000},
			{ReservedBudgetMS: 900001, CampaignTotalMS: 86400000},
			{ReservedBudgetMS: 6000, CampaignTotalMS: 600000, ElapsedMS: -1},
			{ReservedBudgetMS: 6000, CampaignTotalMS: 600000, CleanupElapsedMS: -1},
			{ReservedBudgetMS: 6000, CampaignTotalMS: 600000, CampaignChargedMS: -1},
			{ReservedBudgetMS: 6000, CampaignTotalMS: 600000, CleanupReserveMS: 60001},
		}
		for _, in := range cases {
			_, err := SettleNativeCampaignBudget(in)
			if err == nil {
				t.Fatalf("settlement accepted invalid input %+v", in)
			}
		}
	})
}

func TestNativeCampaignBudgetRoundTripDetail(t *testing.T) {
	// A direct pure-function check that the plan's cleanup reserve is not part
	// of the execution window and the settle ledger never exceeds reserved.
	plan, err := PlanNativeCampaignBudget(NativeCampaignBudgetInput{
		TotalBudgetMS: 600000, RequestedBudgetMS: 60000,
		ProfileMaxDurationMS: 600000, PolicyMaxDurationMS: 600000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ExecutionWindowMS+plan.CleanupReserveMS != plan.ReservedBudgetMS {
		t.Fatalf("execution+cleanup reserve should partition the envelope: %+v", plan)
	}
	out, err := SettleNativeCampaignBudget(NativeCampaignSettlementInput{
		ReservedBudgetMS: plan.ReservedBudgetMS, ElapsedMS: plan.ExecutionWindowMS,
		CleanupElapsedMS: plan.CleanupReserveMS, CleanupReserveMS: plan.CleanupReserveMS,
		CampaignTotalMS: 600000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.LedgerMS > plan.ReservedBudgetMS {
		t.Fatalf("ledger %d exceeds reserved %d", out.LedgerMS, plan.ReservedBudgetMS)
	}
}

func TestNativeCampaignSpecDefaultAttemptBudgetParse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		spec    string
		want    int64
		present bool
		code    string
	}{
		{"absent", `{"engine":"afl++"}`, 0, false, ""},
		{"minimum", `{"default_attempt_budget_ms":6000}`, 6000, true, ""},
		{"maximum", `{"default_attempt_budget_ms":900000}`, 900000, true, ""},
		{"null", `{"default_attempt_budget_ms":null}`, 0, true, "invalid_request"},
		{"string", `{"default_attempt_budget_ms":"10000"}`, 0, true, "invalid_request"},
		{"fraction", `{"default_attempt_budget_ms":10000.5}`, 0, true, "invalid_request"},
		{"exponent", `{"default_attempt_budget_ms":1e4}`, 0, true, "invalid_request"},
		{"negative", `{"default_attempt_budget_ms":-1}`, 0, true, "invalid_request"},
		{"below_min", `{"default_attempt_budget_ms":5999}`, 0, true, "invalid_request"},
		{"above_max", `{"default_attempt_budget_ms":900001}`, 0, true, "invalid_request"},
		{"overflow", `{"default_attempt_budget_ms":9223372036854775808}`, 0, true, "invalid_request"},
		{"boolean", `{"default_attempt_budget_ms":true}`, 0, true, "invalid_request"},
		{"object", `{"default_attempt_budget_ms":{}}`, 0, true, "invalid_request"},
		{"not_object", `null`, 0, false, "invalid_request"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, present, err := nativeCampaignSpecDefaultAttemptBudgetMS([]byte(tc.spec))
			if tc.code != "" {
				requireNativeCampaignCode(t, err, tc.code)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want || present != tc.present {
				t.Fatalf("parse=%d present=%v want %d/%v", got, present, tc.want, tc.present)
			}
		})
	}
}

func TestNativeCampaignSpecDefaultAttemptBudgetCap(t *testing.T) {
	got, err := nativeCampaignDefaultAttemptBudgetCapMS([]byte(`{"default_attempt_budget_ms":10000}`), 6000)
	if err != nil {
		t.Fatal(err)
	}
	if got != 6000 {
		t.Fatalf("spec default above remaining=%d want 6000", got)
	}
	got, err = nativeCampaignDefaultAttemptBudgetCapMS([]byte(`{"engine":"afl++"}`), 600000)
	if err != nil {
		t.Fatal(err)
	}
	if got != NativeCampaignCompatDefaultAttemptBudgetMS {
		t.Fatalf("legacy default=%d want %d", got, NativeCampaignCompatDefaultAttemptBudgetMS)
	}
}
