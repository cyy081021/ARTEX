package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Native Campaign v1 (T4a) single-worker manager.
//
// It is explicitly created, started and closed. The constructor never starts a
// goroutine. Only a committed T3 ClaimNativeCampaignAttempt result can reach the
// runner factory. Lease renewal is a DB CAS; the global resource_hold row (not
// an in-process mutex) is the cross-process exclusion.
var (
	ErrNativeCampaignManagerStarted  = errors.New("native campaign manager already started")
	ErrNativeCampaignManagerClosed   = errors.New("native campaign manager is closed")
	ErrNativeCampaignStartAborted    = errors.New("native campaign runner start aborted before ownership was proven")
	ErrNativeCampaignCloseTimeout    = errors.New("native campaign manager close timed out with unfinished runs")
	errNativeCampaignEOFWithoutFinal = fmt.Errorf("%w: event stream EOF without final", errNativeCampaignProtocolViolation)
)

type nativeCampaignLeaseStore interface {
	RenewNativeCampaignAttemptLease(context.Context, db.NativeCampaignLeaseCommand) (*db.NativeCampaignLeaseResult, error)
	CheckNativeCampaignAttemptStart(context.Context, db.NativeCampaignLeaseIdentity) (*db.NativeCampaignLeaseResult, error)
	MarkNativeCampaignAttemptStarted(context.Context, db.NativeCampaignAttemptStartCommand) (*db.NativeCampaignLeaseResult, error)
	HaltNativeCampaignAttemptForLeaseLoss(context.Context, db.NativeCampaignLeaseHaltCommand) (*db.NativeCampaignLeaseResult, error)
}

type nativeCampaignDBLeaseStore struct{ pg *db.DB }

func (s nativeCampaignDBLeaseStore) RenewNativeCampaignAttemptLease(ctx context.Context, cmd db.NativeCampaignLeaseCommand) (*db.NativeCampaignLeaseResult, error) {
	return s.pg.RenewNativeCampaignAttemptLease(ctx, cmd)
}

func (s nativeCampaignDBLeaseStore) CheckNativeCampaignAttemptStart(ctx context.Context, id db.NativeCampaignLeaseIdentity) (*db.NativeCampaignLeaseResult, error) {
	return s.pg.CheckNativeCampaignAttemptStart(ctx, id)
}

func (s nativeCampaignDBLeaseStore) MarkNativeCampaignAttemptStarted(ctx context.Context, cmd db.NativeCampaignAttemptStartCommand) (*db.NativeCampaignLeaseResult, error) {
	return s.pg.MarkNativeCampaignAttemptStarted(ctx, cmd)
}

func (s nativeCampaignDBLeaseStore) HaltNativeCampaignAttemptForLeaseLoss(ctx context.Context, cmd db.NativeCampaignLeaseHaltCommand) (*db.NativeCampaignLeaseResult, error) {
	return s.pg.HaltNativeCampaignAttemptForLeaseLoss(ctx, cmd)
}

type nativeCampaignCleanupProbe func(context.Context, nativeCampaignCleanupRequest) (nativeCampaignCleanupReport, error)

type nativeCampaignManagerConfig struct {
	CleanupProbe nativeCampaignCleanupProbe
	// Trusted runner-namespace private root; empty disables durable seals.
	RunnerStagingRoot string
	Enabled           bool
	DB                *db.DB
	Service           *nativeCampaignService
	Clock             nativeCampaignClock
	RunnerFactory     nativeCampaignRunnerFactory
	LeaseStore        nativeCampaignLeaseStore
	LeaseTTL          time.Duration
	RenewInterval     time.Duration
	MonitorInterval   time.Duration
	QueueInterval     time.Duration
	StopTimeout       time.Duration
	CleanupTimeout    time.Duration
	ControlTimeout    time.Duration
	StartTimeout      time.Duration
	// DrainTimeout bounds how long a final result waits for trailing events. A
	// runner is allowed to keep Events open after Wait returns; Wait success does
	// not prove the event stream is exhausted.
	DrainTimeout time.Duration
	// EOFTimeout bounds how long a closed Events stream may wait for a final
	// before the manager safely cancels and then aborts the attempt.
	EOFTimeout time.Duration
	InstanceID string
	// StartRaceHook is an internal deterministic-test hook invoked after startup
	// reconciliation and before the final start lock. It lets tests interleave
	// Close with Start without timing-dependent sleeps.
	StartRaceHook func()
	// BeforeStartHook is an internal deterministic-test hook invoked after the
	// run has been registered (active + wg) and immediately before runner.Start.
	BeforeStartHook func()
	// DisableBackground is an internal deterministic-test switch: Start still
	// performs reconciliation but does not launch tickers, so tests call Step and
	// StepLeases directly.
	DisableBackground bool
}

type nativeCampaignManager struct {
	cleanupProbe      nativeCampaignCleanupProbe
	runnerStagingRoot string
	enabled           bool
	pg                *db.DB
	service           *nativeCampaignService
	clock             nativeCampaignClock
	factory           nativeCampaignRunnerFactory
	leases            nativeCampaignLeaseStore
	leaseTTL          time.Duration
	renewInterval     time.Duration
	monitorInterval   time.Duration
	queueInterval     time.Duration
	stopTimeout       time.Duration
	cleanupTimeout    time.Duration
	controlTimeout    time.Duration
	startTimeout      time.Duration
	drainTimeout      time.Duration
	eofTimeout        time.Duration
	instanceID        string
	background        bool
	startRaceHook     func()
	beforeStartHook   func()

	mu             sync.Mutex
	started        bool
	closed         bool
	closeErr       error
	closeDone      chan struct{}
	needsReconcile bool
	reconcileIDs   []int64
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	loopDone       chan struct{}
	// ops counts every allowed Step/claim/start operation from before Claim
	// through all compensation Halt and error recording. opsDone is replaced
	// under mu when the count rises from zero and closed when it returns to
	// zero, so Close can wait without a WaitGroup Add/Wait race.
	ops     int
	opsDone chan struct{}
	active  map[int64]*nativeCampaignRun
	// compensationFailures records pre-run compensation Halt failures that would
	// otherwise disappear before Close inspects any run.
	compensationFailures map[int64]error
	// finalizationFailures survives run removal so a later Close still reports a
	// failed durable finalize/halt instead of seeing an empty tracking set.
	finalizationFailures map[int64]error
	// transports tracks every registered starting/started run until its overall
	// done signal closes. A finalizer may remove business-active ownership while
	// a non-cooperative Wait is still blocked, so Close consults this lifecycle
	// set instead of only the active map.
	transports map[*nativeCampaignRun]struct{}
}

type nativeCampaignRun struct {
	taskID        int64
	campaignID    int64
	attemptID     int64
	attemptNo     int
	fencingToken  int64
	leaseOwner    string
	leaseInstance string
	operatorKind  string
	operatorID    int64
	plan          db.NativeCampaignBudgetPlan
	deadline      db.NativeCampaignDeadline
	startedMono   time.Time
	attempt       *db.NativeCampaignAttempt
	resume        *nativeCampaignResumeObservation // immutable server-generated selection proof
	runner        nativeCampaignRunner
	ctx           context.Context
	cancel        context.CancelFunc
	// done is the single overall-lifecycle completion signal. It closes only
	// after the start/runRunner goroutine has exited, Wait and event handling
	// have settled (or never started), and the unique finalization owner has
	// finished Cleanup plus Halt/Finalize persistence. An empty active map or a
	// returned Wait alone is never treated as lifecycle completion.
	done        chan struct{}
	doneOnce    sync.Once
	localDone   chan struct{}
	localOnce   sync.Once
	waitDone    chan struct{}
	waitStarted bool
	// transportDone is retained for diagnostics/tests; it now closes with the
	// full lifecycle, not merely when Wait returns.
	transportDone    chan struct{}
	transportOnce    sync.Once
	finalizationDone chan struct{}
	finalizationOnce sync.Once
	// startGate serializes "decide to call Start" against beginFinalization.
	// productionDone closes after factory publication (runner stored first).
	// startAttemptDone closes when this producer will never call Start again.
	startGate        sync.Mutex
	productionDone   chan struct{}
	productionOnce   sync.Once
	startAttemptDone chan struct{}
	startAttemptOnce sync.Once

	mu                 sync.Mutex
	controlMu          sync.Mutex
	controlAck         string
	controlPending     string
	controlAttempts    int
	controlFailed      bool
	statePending       string
	stateAttempts      int
	stateLastError     string
	requestedState     string
	requestedConfirmed bool
	leaseExpires       time.Time
	leaseFailures      int
	deadlineReached    bool
	deadlineStop       bool
	leaseLost          bool
	leaseLostReason    string
	haltErr            error
	protocolErr        error
	eventsClosed       bool
	eofWithoutFinal    bool
	drainTruncated     bool
	drainTimedOut      bool
	finalSeen          bool
	finalizing         bool
	finalized          bool
	finalizationErr    error
	abortRequested     bool
	lifecycle          string
	evidence           nativeCampaignEvidenceBudget
}

const (
	nativeCampaignRunStarting   = "starting"
	nativeCampaignRunRunning    = "running"
	nativeCampaignRunFinalizing = "finalizing"
	nativeCampaignRunFinalized  = "finalized"
)

func (r *nativeCampaignRun) markRunning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lifecycle != nativeCampaignRunStarting {
		return false
	}
	r.lifecycle = nativeCampaignRunRunning
	return true
}

func (r *nativeCampaignRun) finalizationStarted() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.finalizing || r.finalized
}

func (r *nativeCampaignRun) beginFinalization() bool {
	// Serialize with the producer's "may I call Start?" decision. If Start is in
	// progress (or about to be), finalization waits for it to return; if
	// finalization wins first, the producer must not Start the late runner.
	r.startGate.Lock()
	defer r.startGate.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finalizing || r.finalized {
		return false
	}
	r.finalizing = true
	r.lifecycle = nativeCampaignRunFinalizing
	return true
}

// publishFactoryResult records the factory publication and closes
// productionDone. The runner is stored before the channel closes so the
// finalization owner can observe and clean a late partial transport.
func (r *nativeCampaignRun) publishFactoryResult(runner nativeCampaignRunner) {
	if runner != nil {
		r.setRunner(runner)
	}
	r.productionOnce.Do(func() { close(r.productionDone) })
}

// skipStartAttempt is used when the producer will not call Start at all.
func (r *nativeCampaignRun) skipStartAttempt() {
	r.startAttemptOnce.Do(func() { close(r.startAttemptDone) })
}

// beginStartAttempt reports whether the producer may call Start. On true the
// caller holds startGate until endStartAttempt. On false the producer must hand
// the already-published runner to the finalization owner and never Start it.
func (r *nativeCampaignRun) beginStartAttempt() bool {
	r.startGate.Lock()
	r.mu.Lock()
	finalizing := r.finalizing || r.finalized
	r.mu.Unlock()
	if finalizing {
		r.startGate.Unlock()
		r.skipStartAttempt()
		return false
	}
	return true
}

func (r *nativeCampaignRun) endStartAttempt() {
	r.skipStartAttempt()
	r.startGate.Unlock()
}

// awaitResourceHandoff blocks a finalization owner until the producer has
// published the factory result and will never call Start again. A
// non-cooperative factory therefore keeps the run registered instead of being
// mistaken for "no resource".
func (r *nativeCampaignRun) awaitResourceHandoff() {
	<-r.productionDone
	<-r.startAttemptDone
}

func (r *nativeCampaignRun) endFinalization() {
	r.mu.Lock()
	r.finalizing = false
	r.finalized = true
	r.lifecycle = nativeCampaignRunFinalized
	r.mu.Unlock()
}

func (r *nativeCampaignRun) isFinalized() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.finalized
}

// recordFinalizationError records a failure to persist the terminal/failed
// state. Cleanup being unknown is not itself a close error; failure to write a
// durable hold is.
func (r *nativeCampaignRun) recordFinalizationError(err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	if r.finalizationErr == nil {
		r.finalizationErr = err
	}
	r.mu.Unlock()
}

func (r *nativeCampaignRun) finalizationFailure() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.finalizationErr
}

// waitSettled reports whether the Wait goroutine has returned. A non-cooperative
// runner can leave Wait blocked after its context is canceled; Close must not
// report success in that case.
func (r *nativeCampaignRun) waitSettled() bool {
	r.mu.Lock()
	started := r.waitStarted
	r.mu.Unlock()
	if !started {
		return true
	}
	select {
	case <-r.waitDone:
		return true
	default:
		return false
	}
}

func (r *nativeCampaignRun) identity() db.NativeCampaignLeaseIdentity {
	return db.NativeCampaignLeaseIdentity{
		TaskID: r.taskID, CampaignID: r.campaignID, AttemptID: r.attemptID,
		FencingToken: r.fencingToken, LeaseOwner: r.leaseOwner, LeaseInstance: r.leaseInstance,
	}
}

func (r *nativeCampaignRun) expectation() nativeCampaignFrameExpectation {
	return nativeCampaignFrameExpectation{
		RequestID: fmt.Sprintf("campaign-%d-attempt-%d", r.campaignID, r.attemptID),
		TaskID:    r.taskID, CampaignID: r.campaignID, AttemptID: r.attemptID,
		FencingToken: r.fencingToken,
	}
}

type nativeCampaignReconciliationError struct {
	AttemptIDs []int64
}

func (e *nativeCampaignReconciliationError) Error() string {
	if e == nil {
		return ErrNativeCampaignReconciliationRequired.Error()
	}
	return fmt.Sprintf("%s: residual attempt ids %v", ErrNativeCampaignReconciliationRequired.Error(), e.AttemptIDs)
}

func (e *nativeCampaignReconciliationError) Unwrap() error {
	return ErrNativeCampaignReconciliationRequired
}

type nativeCampaignCloseTimeoutError struct {
	AttemptIDs []int64
	Active     int
}

func (e *nativeCampaignCloseTimeoutError) Error() string {
	if e == nil {
		return ErrNativeCampaignCloseTimeout.Error()
	}
	return fmt.Sprintf("%s: active=%d unfinished_attempts=%v", ErrNativeCampaignCloseTimeout.Error(), e.Active, e.AttemptIDs)
}

func (e *nativeCampaignCloseTimeoutError) Unwrap() error {
	return ErrNativeCampaignCloseTimeout
}

func newNativeCampaignManager(cfg nativeCampaignManagerConfig) (*nativeCampaignManager, error) {
	if cfg.DB == nil || cfg.Service == nil {
		return nil, errors.New("native campaign manager requires a database and service")
	}
	if cfg.Clock == nil {
		cfg.Clock = nativeCampaignSystemClock{}
	}
	if cfg.LeaseStore == nil {
		cfg.LeaseStore = nativeCampaignDBLeaseStore{pg: cfg.DB}
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = time.Duration(db.NativeCampaignDefaultLeaseMS) * time.Millisecond
	}
	if cfg.RenewInterval <= 0 {
		cfg.RenewInterval = 5 * time.Second
	}
	if cfg.MonitorInterval <= 0 {
		cfg.MonitorInterval = time.Second
	}
	if cfg.QueueInterval <= 0 {
		cfg.QueueInterval = time.Second
	}
	if cfg.StopTimeout <= 0 {
		cfg.StopTimeout = 10 * time.Second
	}
	if cfg.CleanupTimeout <= 0 {
		cfg.CleanupTimeout = time.Duration(db.NativeCampaignCleanupHardTimeoutMS) * time.Millisecond
	}
	if cfg.ControlTimeout <= 0 {
		cfg.ControlTimeout = 3 * time.Second
	}
	if cfg.StartTimeout <= 0 {
		cfg.StartTimeout = 10 * time.Second
	}
	if cfg.DrainTimeout <= 0 {
		cfg.DrainTimeout = time.Second
	}
	if cfg.EOFTimeout <= 0 {
		cfg.EOFTimeout = time.Second
	}
	if cfg.InstanceID == "" {
		cfg.InstanceID = fmt.Sprintf("campaign-manager-%d", time.Now().UnixNano())
	}
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	return &nativeCampaignManager{
		ctx: lifecycleCtx, cancel: lifecycleCancel, cleanupProbe: cfg.CleanupProbe,
		enabled: cfg.Enabled, pg: cfg.DB, service: cfg.Service, clock: cfg.Clock,
		factory: cfg.RunnerFactory, leases: cfg.LeaseStore,
		leaseTTL: cfg.LeaseTTL, renewInterval: cfg.RenewInterval,
		monitorInterval: cfg.MonitorInterval, queueInterval: cfg.QueueInterval,
		stopTimeout: cfg.StopTimeout, cleanupTimeout: cfg.CleanupTimeout,
		controlTimeout: cfg.ControlTimeout, startTimeout: cfg.StartTimeout,
		drainTimeout: cfg.DrainTimeout, eofTimeout: cfg.EOFTimeout,
		runnerStagingRoot: cfg.RunnerStagingRoot, instanceID: cfg.InstanceID, startRaceHook: cfg.StartRaceHook,
		beforeStartHook:      cfg.BeforeStartHook,
		background:           !cfg.DisableBackground,
		active:               map[int64]*nativeCampaignRun{},
		transports:           map[*nativeCampaignRun]struct{}{},
		compensationFailures: map[int64]error{},
		finalizationFailures: map[int64]error{},
		closeDone:            make(chan struct{}),
		loopDone:             make(chan struct{}),
		opsDone:              closedNativeCampaignSignal(),
	}, nil
}

func closedNativeCampaignSignal() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func (m *nativeCampaignManager) needsAuthorization() bool {
	return m == nil || !m.enabled
}

// Start performs startup reconciliation and (unless disabled for deterministic
// tests) launches one scheduler goroutine. It never auto-starts a runner for an
// attempt found before Start.
func (m *nativeCampaignManager) Start(ctx context.Context) error {
	if m == nil {
		return ErrNativeCampaignDisabled
	}
	// Startup now performs fenced DB reconciliation, so Close must include it
	// in the same admitted-operation barrier as claim/renewal/finalization.
	if !m.beginOperation() {
		return ErrNativeCampaignManagerClosed
	}
	defer m.endOperation()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrNativeCampaignManagerClosed
	}
	if m.started {
		m.mu.Unlock()
		return ErrNativeCampaignManagerStarted
	}
	if !m.enabled {
		m.mu.Unlock()
		return ErrNativeCampaignDisabled
	}
	if m.factory == nil || m.leases == nil || m.service == nil {
		m.mu.Unlock()
		return errors.New("native campaign manager dependencies are incomplete")
	}
	m.mu.Unlock()

	// This phase never probes or releases resources. It only interrupts an
	// expired, still-identical owner under DB locks; every residual hold keeps
	// scheduling disabled until trustworthy cleanup is implemented/proven.
	startupCtx, startupCancel := context.WithTimeout(ctx, m.stopTimeout)
	defer startupCancel()
	type recoveryCandidate struct {
		identity db.NativeCampaignLeaseIdentity
		state    string
	}
	var candidates []recoveryCandidate
	var residual []int64
	rows, err := m.pg.QueryContext(startupCtx, `SELECT task_id,campaign_id,id,fencing_token,lease_owner,lease_instance,state FROM native_campaign_attempts
		WHERE resource_hold OR state IN ('claimed','launching','running','stopping','collecting','cleaning')
		ORDER BY id LIMIT 32`)
	if err != nil {
		return fmt.Errorf("native campaign startup reconciliation: %w", err)
	}
	for rows.Next() {
		var candidate recoveryCandidate
		id := &candidate.identity
		if err := rows.Scan(&id.TaskID, &id.CampaignID, &id.AttemptID, &id.FencingToken, &id.LeaseOwner, &id.LeaseInstance, &candidate.state); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, candidate)
		residual = append(residual, id.AttemptID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, candidate := range candidates {
		switch candidate.state {
		case "claimed", "launching", "running", "stopping", "collecting", "cleaning":
			if _, err := m.pg.ReconcileExpiredNativeCampaignAttempt(startupCtx, candidate.identity); err != nil && db.NativeCampaignErrorCode(err) != "lease_active" {
				return fmt.Errorf("native campaign expired-owner reconciliation: %w", err)
			}
		}
	}
	if len(residual) > 0 {
		m.mu.Lock()
		m.needsReconcile = true
		m.reconcileIDs = append([]int64(nil), residual...)
		m.mu.Unlock()
		return &nativeCampaignReconciliationError{AttemptIDs: residual}
	}
	if m.startRaceHook != nil {
		m.startRaceHook()
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrNativeCampaignManagerClosed
	}
	if m.started {
		m.mu.Unlock()
		return ErrNativeCampaignManagerStarted
	}
	m.needsReconcile = false
	m.reconcileIDs = nil
	m.started = true
	if m.background {
		m.wg.Add(1)
		go m.loop()
	} else {
		// No scheduler goroutine was launched; the lifecycle loop is already
		// settled for Close purposes.
		close(m.loopDone)
	}
	m.mu.Unlock()
	return nil
}

func (m *nativeCampaignManager) loop() {
	defer m.wg.Done()
	defer close(m.loopDone)
	queue := time.NewTicker(m.queueInterval)
	defer queue.Stop()
	renew := time.NewTicker(m.renewInterval)
	defer renew.Stop()
	monitor := time.NewTicker(m.monitorInterval)
	defer monitor.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-queue.C:
			m.stepWithContext(m.ctx)
		case <-monitor.C:
			m.stepWithContext(m.ctx)
		case <-renew.C:
			m.stepLeasesWithContext(m.ctx)
		}
	}
}

func (m *nativeCampaignManager) stepWithContext(ctx context.Context) {
	defer func() { _ = recover() }()
	_ = m.Step(ctx)
}

// Step runs one deterministic scheduler/watcher iteration. Tests use it instead
// of sleeping on tickers.
func (m *nativeCampaignManager) Step(ctx context.Context) error {
	if !m.beginOperation() {
		return ErrNativeCampaignManagerClosed
	}
	defer m.endOperation()
	if err := m.requireRunning(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, m.stopTimeout)
	defer cancel()
	runs := m.snapshotRuns()
	for _, run := range runs {
		if err := m.monitorRun(ctx, run); err != nil {
			return err
		}
	}
	if len(runs) > 0 {
		return nil
	}
	return m.scheduleOne(ctx)
}

func (m *nativeCampaignManager) stepLeasesWithContext(ctx context.Context) {
	defer func() { _ = recover() }()
	_ = m.StepLeases(ctx)
}

// StepLeases renews every owned lease once. Three consecutive failures or an
// expired lease stop only this manager's runner and mark the attempt interrupted
// with cleanup unknown; no hold is released and no DB success is claimed.
func (m *nativeCampaignManager) StepLeases(ctx context.Context) error {
	if !m.beginOperation() {
		return ErrNativeCampaignManagerClosed
	}
	defer m.endOperation()
	if err := m.requireRunning(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, m.stopTimeout)
	defer cancel()
	runs := m.snapshotRuns()
	var firstErr error
	for _, run := range runs {
		run.mu.Lock()
		lifecycle := run.lifecycle
		run.mu.Unlock()
		// Lease renewal is a post-start operation. The start-permission check is
		// separate and must not consume the renewal-failure budget before Start
		// has been confirmed.
		if lifecycle != nativeCampaignRunRunning {
			continue
		}
		if m.expiredLease(run) {
			if err := m.stopLeaseLost(run, "lease_expired"); err != nil && firstErr == nil {
				firstErr = err
			}
			continue
		}
		renewed, err := m.renewRunnerLease(ctx, run)
		if err == nil {
			continue
		}
		if renewed {
			// The database renewed, but the runner did not acknowledge the
			// same fixed authority. Fail closed, never report lease success.
			if stopErr := m.stopLeaseLost(run, "runner_heartbeat_failed"); stopErr != nil && firstErr == nil {
				firstErr = stopErr
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if db.NativeCampaignErrorCode(err) == "lease_lost" {
			if stopErr := m.stopLeaseLost(run, "lease_lost"); stopErr != nil && firstErr == nil {
				firstErr = stopErr
			}
			continue
		}
		run.mu.Lock()
		run.leaseFailures++
		failures := run.leaseFailures
		run.mu.Unlock()
		if failures >= 3 {
			if stopErr := m.stopLeaseLost(run, "lease_renew_failed"); stopErr != nil && firstErr == nil {
				firstErr = stopErr
			}
		} else if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// renewRunnerLease serializes DB renewal and its runner ACK with existing
// controls; it introduces no retry clock or second pending-request ledger.
func (m *nativeCampaignManager) renewRunnerLease(ctx context.Context, run *nativeCampaignRun) (bool, error) {
	run.controlMu.Lock()
	defer run.controlMu.Unlock()
	run.mu.Lock()
	running := run.lifecycle == nativeCampaignRunRunning && run.controlAck == "" && run.controlPending == ""
	oldLease := run.leaseExpires
	run.mu.Unlock()
	if !running {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	result, err := m.leases.RenewNativeCampaignAttemptLease(ctx, db.NativeCampaignLeaseCommand{NativeCampaignLeaseIdentity: run.identity(), LeaseMS: int64(m.leaseTTL / time.Millisecond)})
	if err != nil {
		return false, err
	}
	if result == nil || result.Attempt == nil {
		return true, errors.New("successful lease renewal omitted authoritative attempt")
	}
	a := result.Attempt
	if a.ID != run.attemptID || a.TaskID != run.taskID || a.CampaignID != run.campaignID || a.FencingToken != run.fencingToken || a.LeaseOwner != run.leaseOwner || a.LeaseInstance != run.leaseInstance || result.LeaseExpiresAt.IsZero() || !result.LeaseExpiresAt.Equal(a.LeaseExpiresAt) {
		return true, errors.New("lease renewal authority identity/deadline mismatch")
	}
	cutoff := result.LeaseExpiresAt
	if cutoff.After(run.deadline.ExecutionDeadline) {
		cutoff = run.deadline.ExecutionDeadline
	}
	now := time.Now()
	if !cutoff.After(now) || !oldLease.After(now) {
		return true, errors.New("lease expired before runner heartbeat")
	}
	runner := run.getRunner()
	if runner == nil {
		return true, errors.New("renewed attempt has no runner")
	}
	end := now.Add(m.controlTimeout)
	if oldLease.Before(end) {
		end = oldLease
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(end) {
		end = deadline
	}
	controlCtx, cancel := context.WithDeadline(run.ctx, end)
	err = runner.Control(controlCtx, nativeCampaignRunnerControl{RequestID: fmt.Sprintf("%s-lease-%d", run.expectation().RequestID, cutoff.UnixNano()), Action: "heartbeat", LeaseMS: int64(m.leaseTTL / time.Millisecond), LeaseDeadline: cutoff.UTC().Format(time.RFC3339Nano)})
	cancel()
	if err != nil {
		return true, err
	}
	if !time.Now().Before(oldLease) {
		return true, errors.New("runner heartbeat acknowledgement arrived after old lease")
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.lifecycle != nativeCampaignRunRunning || run.ctx.Err() != nil {
		return true, errors.New("attempt stopped during runner heartbeat")
	}
	run.leaseFailures = 0
	run.leaseExpires = result.LeaseExpiresAt
	return true, nil
}

// beginOperation registers one allowed scheduler/claim/start operation. It is
// the close barrier: after Close sets closed under the same mutex, no new
// operation can start. The operation stays registered through every
// compensation Halt and error-recording step so Close cannot observe an empty
// run set while a claim is still being compensated.
func (m *nativeCampaignManager) beginOperation() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	if m.ops == 0 {
		m.opsDone = make(chan struct{})
	}
	m.ops++
	return true
}

func (m *nativeCampaignManager) endOperation() {
	m.mu.Lock()
	m.ops--
	if m.ops == 0 {
		close(m.opsDone)
	}
	m.mu.Unlock()
}

func (m *nativeCampaignManager) operationDone() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.opsDone
}

func (m *nativeCampaignManager) closedSnapshot() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func (m *nativeCampaignManager) requireRunning() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrNativeCampaignManagerClosed
	}
	if !m.started {
		return errors.New("native campaign manager is not started")
	}
	if m.needsReconcile {
		return &nativeCampaignReconciliationError{AttemptIDs: append([]int64(nil), m.reconcileIDs...)}
	}
	return nil
}

func (m *nativeCampaignManager) snapshotRuns() []*nativeCampaignRun {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*nativeCampaignRun, 0, len(m.active))
	for _, run := range m.active {
		out = append(out, run)
	}
	return out
}

func (m *nativeCampaignManager) expiredLease(run *nativeCampaignRun) bool {
	run.mu.Lock()
	defer run.mu.Unlock()
	return !run.leaseExpires.IsZero() && !m.clock.Now().Before(run.leaseExpires)
}

func (m *nativeCampaignManager) scheduleOne(ctx context.Context) error {
	if m.closedSnapshot() {
		return ErrNativeCampaignManagerClosed
	}
	rows, err := m.pg.QueryContext(ctx, `SELECT id,task_id FROM native_campaigns
		WHERE state='queued' AND desired_state='running' ORDER BY id LIMIT 8`)
	if err != nil {
		return err
	}
	var campaigns [][2]int64
	for rows.Next() {
		var campaignID, taskID int64
		if err := rows.Scan(&campaignID, &taskID); err != nil {
			rows.Close()
			return err
		}
		campaigns = append(campaigns, [2]int64{taskID, campaignID})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, campaign := range campaigns {
		if m.closedSnapshot() {
			return ErrNativeCampaignManagerClosed
		}
		outcome, err := m.service.Claim(ctx, campaign[0], campaign[1], m.instanceID)
		if err != nil {
			if code := db.NativeCampaignErrorCode(err); code == "resource_held" || code == "cleanup_unknown" {
				return nil
			}
			continue
		}
		if outcome == nil || outcome.Claim == nil || outcome.Claim.Attempt == nil {
			continue
		}
		return m.startClaimedRun(ctx, outcome)
	}
	return nil
}

func (m *nativeCampaignManager) plannedResources(attempt *db.NativeCampaignAttempt) json.RawMessage {
	nonce := fmt.Sprintf("%d-%d", attempt.ID, attempt.FencingToken)
	value := map[string]any{
		"container_name": fmt.Sprintf("artex-campaign-%d-%d-%s", attempt.CampaignID, attempt.ID, nonce),
		"staging_nonce":  nonce,
		"labels": map[string]string{
			"artex.task_id":       fmt.Sprintf("%d", attempt.TaskID),
			"artex.campaign_id":   fmt.Sprintf("%d", attempt.CampaignID),
			"artex.attempt_id":    fmt.Sprintf("%d", attempt.ID),
			"artex.fencing_token": fmt.Sprintf("%d", attempt.FencingToken),
			"artex.owner":         "artex-native-campaign",
		},
	}
	if m.runnerStagingRoot != "" {
		names := nativeCampaignResourceNames(attempt.CampaignID, attempt.ID, attempt.FencingToken)
		value["resource_plan"] = &nativeCampaignResourcePlan{Version: 1, TaskID: attempt.TaskID, CampaignID: attempt.CampaignID, AttemptID: attempt.ID, FencingToken: attempt.FencingToken, StagingRoot: m.runnerStagingRoot, StagingBasename: names[0] + "-stage", ContainerNames: names}
	}
	raw, _ := json.Marshal(value)
	return raw
}

// nativeCampaignEarliestStartDeadline is the earliest of the bounded start
// timeout, the absolute execution deadline, the budget envelope deadline and the
// lease expiry. The bool is false if any absolute deadline has already passed.
func nativeCampaignEarliestStartDeadline(now time.Time, startTimeout time.Duration, execution, envelope, lease time.Time) (time.Time, bool) {
	deadline := now.Add(startTimeout)
	for _, candidate := range []time.Time{execution, envelope, lease} {
		if !candidate.IsZero() && candidate.Before(deadline) {
			deadline = candidate
		}
	}
	for _, candidate := range []time.Time{execution, envelope, lease} {
		if !candidate.IsZero() && !now.Before(candidate) {
			return deadline, false
		}
	}
	return deadline, true
}

func (m *nativeCampaignManager) startDeadline(run *nativeCampaignRun, now time.Time) (time.Time, bool) {
	run.mu.Lock()
	lease := run.leaseExpires
	run.mu.Unlock()
	return nativeCampaignEarliestStartDeadline(now, m.startTimeout,
		run.deadline.ExecutionDeadline, run.deadline.EnvelopeDeadline, lease)
}

// nativeCampaignStartParameters reads only immutable execution parameters. It
// cannot supply authority, paths, identity, ownership or accounting deadlines.
func nativeCampaignStartParameters(spec json.RawMessage) (nativeCampaignRunnerStart, error) {
	var start nativeCampaignRunnerStart
	var fields map[string]json.RawMessage
	if len(spec) == 0 || len(spec) > 262144 || json.Unmarshal(spec, &fields) != nil || fields == nil {
		return start, errors.New("invalid campaign spec object")
	}
	decode := func(key string, target any) error {
		raw, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("campaign spec requires %s", key)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return fmt.Errorf("invalid campaign spec %s: %w", key, err)
		}
		return nil
	}
	var argv []json.RawMessage
	if err := decode("argv", &argv); err != nil {
		return start, err
	}
	if len(argv) > 64 {
		return start, errors.New("too many campaign arguments")
	}
	start.Argv = make([]string, len(argv))
	placeholders := 0
	for i, raw := range argv {
		if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &start.Argv[i]) != nil {
			return start, errors.New("campaign argv entries must be strings")
		}
		arg := start.Argv[i]
		if len(arg) > 4096 || strings.ContainsRune(arg, 0) || strings.Contains(arg, "@@") || (strings.Contains(arg, "{input}") && arg != "{input}") {
			return start, errors.New("invalid campaign argument")
		}
		if arg == "{input}" {
			placeholders++
		}
	}
	if err := decode("input_mode", &start.InputMode); err != nil {
		return start, err
	}
	if (start.InputMode == "stdin" && placeholders != 0) || (start.InputMode == "file" && placeholders != 1) || (start.InputMode != "stdin" && start.InputMode != "file") {
		return start, errors.New("invalid campaign input mode or placeholder")
	}
	if err := decode("seeds", &start.Seeds); err != nil {
		return start, err
	}
	if len(start.Seeds) < 1 || len(start.Seeds) > NativeCampaignMaxSeeds {
		return start, errors.New("campaign spec requires 1..32 seeds")
	}
	if err := decode("max_executions", &start.MaxExecutions); err != nil {
		return start, err
	}
	if start.MaxExecutions < 100 || start.MaxExecutions > 1000000 {
		return start, errors.New("invalid campaign max_executions")
	}
	if err := decode("max_crashes", &start.MaxCrashes); err != nil {
		return start, err
	}
	if start.MaxCrashes < 1 || start.MaxCrashes > 8 {
		return start, errors.New("invalid campaign max_crashes")
	}
	// Canonical base64, SHA-256 and decoded per-object/total bounds are checked
	// by Start.Validate after the authoritative identity/profile are attached.
	return start, nil
}

func (m *nativeCampaignManager) startClaimedRun(ctx context.Context, outcome *nativeCampaignClaimOutcome) error {
	attempt := outcome.Claim.Attempt
	campaign := outcome.Claim
	if campaign == nil {
		return errors.New("native campaign claim result is incomplete")
	}
	// A claim already committed before Close must be compensated, not started.
	if m.closedSnapshot() {
		_ = m.haltOwnedNoStart(attempt, "manager_stopped_after_claim", 0)
		return ErrNativeCampaignManagerClosed
	}
	// Re-check authorization in the claim -> start gap. A revoked operator or
	// changed image must not launch anything.
	reauth, err := m.service.AuthorizeClaimAfterClaim(ctx, attempt.TaskID, attempt.CampaignID, outcome.Auth.ImageID)
	if err != nil {
		_ = m.haltOwnedNoStart(attempt, "authorization_revoked_before_start", 0)
		return err
	}
	if reauth.Campaign == nil {
		_ = m.haltOwnedNoStart(attempt, "authorization_incomplete", 0)
		return errors.New("campaign authorization is incomplete")
	}
	var loader nativeCampaignCheckpointLoader
	if reauth.Campaign.LatestCheckpointID != nil {
		var ok bool
		loader, ok = m.service.checkpoints.(nativeCampaignCheckpointLoader)
		if !ok {
			_ = m.haltOwnedNoStart(attempt, "checkpoint_restore_unavailable", 0)
			return errors.New("checkpoint restore is not connected; refusing initial-seed restart")
		}
	}
	parameters, err := nativeCampaignStartParameters(reauth.Campaign.Spec)
	if err != nil {
		_ = m.haltOwnedNoStart(attempt, "invalid_start_spec", 0)
		return err
	}
	startedMono := m.clock.Now()
	planned := m.plannedResources(attempt)
	started, err := m.leases.MarkNativeCampaignAttemptStarted(ctx, db.NativeCampaignAttemptStartCommand{
		NativeCampaignLeaseIdentity: db.NativeCampaignLeaseIdentity{
			TaskID: attempt.TaskID, CampaignID: attempt.CampaignID, AttemptID: attempt.ID,
			FencingToken: attempt.FencingToken, LeaseOwner: attempt.LeaseOwner, LeaseInstance: attempt.LeaseInstance,
		},
		Phase: "startup", OwnedResources: planned,
	})
	if err != nil {
		_ = m.haltOwnedNoStart(attempt, "start_cas_failed", 0)
		return err
	}
	attempt = started.Attempt
	if attempt.StartedAt == nil {
		_ = m.haltOwnedNoStart(attempt, "started_at_not_persisted", 0)
		return errors.New("started_at was not persisted before runner start")
	}
	deadline := campaign.Plan.Deadlines(*attempt.StartedAt)
	runCtx, cancel := context.WithCancel(m.ctx)
	run := &nativeCampaignRun{
		taskID: attempt.TaskID, campaignID: attempt.CampaignID, attemptID: attempt.ID,
		attemptNo: attempt.AttemptNo, fencingToken: attempt.FencingToken,
		leaseOwner: attempt.LeaseOwner, leaseInstance: attempt.LeaseInstance,
		operatorKind: attempt.OperatorKind, operatorID: attempt.OperatorID,
		plan: campaign.Plan, deadline: deadline, startedMono: startedMono,
		attempt: attempt, ctx: runCtx, cancel: cancel, done: make(chan struct{}),
		localDone:        make(chan struct{}),
		waitDone:         make(chan struct{}),
		transportDone:    make(chan struct{}),
		finalizationDone: make(chan struct{}),
		productionDone:   make(chan struct{}),
		startAttemptDone: make(chan struct{}),
		leaseExpires:     attempt.LeaseExpiresAt, lifecycle: nativeCampaignRunStarting,
	}
	initialLease := attempt.LeaseExpiresAt
	if initialLease.After(deadline.ExecutionDeadline) {
		initialLease = deadline.ExecutionDeadline
	}
	start := nativeCampaignRunnerStart{
		TaskID: attempt.TaskID, RequestID: run.expectation().RequestID,
		CampaignID: attempt.CampaignID, AttemptID: attempt.ID, AttemptNo: attempt.AttemptNo,
		FencingToken: attempt.FencingToken, LeaseOwner: attempt.LeaseOwner,
		LeaseInstance: attempt.LeaseInstance, LeaseMS: int64(m.leaseTTL / time.Millisecond), LeaseDeadline: initialLease.UTC().Format(time.RFC3339Nano),
		ArtifactPath: reauth.Artifact.Path, SHA256: reauth.Artifact.SHA256,
		Argv: parameters.Argv, InputMode: parameters.InputMode, Seeds: parameters.Seeds,
		MaxExecutions: parameters.MaxExecutions, MaxCrashes: parameters.MaxCrashes,
		AttemptBudgetMS:      campaign.Plan.ReservedBudgetMS,
		ExecutionWindowMS:    campaign.Plan.ExecutionWindowMS,
		ExecutionDeadline:    deadline.ExecutionDeadline.UTC().Format(time.RFC3339Nano),
		EnvelopeDeadline:     deadline.EnvelopeDeadline.UTC().Format(time.RFC3339Nano),
		CleanupReserveMS:     campaign.Plan.CleanupReserveMS,
		CleanupHardTimeoutMS: db.NativeCampaignCleanupHardTimeoutMS,
		Profile: nativeCampaignRunnerProfile{
			Image: reauth.Profile.Settings["image"].(string), ImageID: reauth.ImageID,
			FuzzEnabled:  reauth.Profile.Settings["fuzz_enabled"] == true,
			Enabled:      reauth.Profile.Settings["enabled"] != false,
			Network:      nativeCampaignProfileNetwork(reauth.Profile),
			ReadOnlyRoot: nativeCampaignProfileReadOnly(reauth.Profile),
			MaxDuration:  reauth.ProfileMaxDurationMS,
		},
		OwnedResources: planned,
	}
	if err := start.Validate(); err != nil {
		_ = m.haltOwnedNoStart(attempt, "invalid_start_frame", elapsedMS(m.clock.Now(), startedMono))
		cancel()
		return err
	}
	// A single absolute start deadline is derived before any runner dependency
	// is invoked, and it never moves later for this attempt.
	overallDeadline, ok := m.startDeadline(run, m.clock.Now())
	if !ok {
		cancel()
		_ = m.finalizeStartFailure(attempt, run, nil, ErrNativeCampaignStartAborted)
		return fmt.Errorf("%w: absolute deadline or lease expired before the factory", ErrNativeCampaignStartAborted)
	}
	if loader != nil {
		// Restoration is charged inside the already persisted attempt window,
		// not an unbudgeted pre-start read. It cannot extend start or lease.
		loadCtx, loadCancel := context.WithDeadline(runCtx, overallDeadline)
		restored, loadErr := loader.LoadCheckpoint(loadCtx, run.taskID, run.campaignID, *reauth.Campaign.LatestCheckpointID)
		loadCancel()
		if loadErr == nil {
			loadErr = restored.validateBinding(run.taskID, run.campaignID, *reauth.Campaign.LatestCheckpointID, run.attemptID)
		}
		if loadErr == nil {
			start.Seeds = append([]nativeCampaignSeed(nil), restored.Seeds...)
			loadErr = start.Validate()
		}
		if loadErr != nil {
			_ = m.haltOwnedNoStart(attempt, "checkpoint_restore_failed", elapsedMS(m.clock.Now(), startedMono))
			cancel()
			return fmt.Errorf("checkpoint restore failed: %w", loadErr)
		}
		proof := restored.Observation
		proof.Selected = append([]nativeCampaignResumeSeed(nil), proof.Selected...)
		run.resume = &proof
	}
	// Persisted ownership/authorization gate before the factory creates a
	// transport.
	factoryCtx, factoryCancel := context.WithDeadline(runCtx, overallDeadline)
	if err := m.preStartCheck(factoryCtx, run, reauth.ImageID); err != nil {
		factoryCancel()
		cancel()
		_ = m.finalizeStartFailure(attempt, run, nil, err)
		return err
	}
	// Register the starting lifecycle and transport BEFORE entering the factory.
	// A blocked factory is therefore visible to Close; early returns below all
	// own bounded cleanup and converge through the single finalizer.
	if err := m.registerRun(run); err != nil {
		factoryCancel()
		cancel()
		_ = m.finalizeStartFailure(attempt, run, nil, err)
		return err
	}
	runner, err := m.factory(factoryCtx, start)
	factoryCancel()
	// Publish the factory result exactly once before any finalizer can treat a
	// temporarily nil runner as "no resource". The runner is stored before
	// productionDone closes, so a finalizer that won during the factory wait can
	// observe and clean a late partial transport.
	run.publishFactoryResult(runner)
	if err != nil || runner == nil {
		run.skipStartAttempt()
		m.finishRegisteredStart(run, attempt, runner, err, "runner_factory_failed")
		return err
	}
	// Serialize the decision to call Start with finalization. If another
	// finalizer already won, this late runner is handed over for cleanup and is
	// never started.
	if !run.beginStartAttempt() {
		m.finishRegisteredStart(run, attempt, runner, ErrNativeCampaignManagerClosed, "manager_closed_after_factory")
		return ErrNativeCampaignManagerClosed
	}
	failStart := func(startErr error, reason string) error {
		run.endStartAttempt()
		m.finishRegisteredStart(run, attempt, runner, startErr, reason)
		return startErr
	}
	// The final deadline is min(original overall deadline, freshly read absolute
	// execution/envelope/lease boundaries). Factory time can never buy a fresh
	// StartTimeout.
	freshDeadline, ok := m.startDeadline(run, m.clock.Now())
	if !ok {
		return failStart(fmt.Errorf("%w: absolute deadline or lease expired before start", ErrNativeCampaignStartAborted), "start_deadline_exceeded")
	}
	finalDeadline := freshDeadline
	if overallDeadline.Before(finalDeadline) {
		finalDeadline = overallDeadline
	}
	if !m.clock.Now().Before(finalDeadline) {
		return failStart(fmt.Errorf("%w: original start deadline passed while the factory ran", ErrNativeCampaignStartAborted), "start_deadline_exceeded")
	}
	startCtx, startCancel := context.WithDeadline(runCtx, finalDeadline)
	if err := m.preStartCheck(startCtx, run, reauth.ImageID); err != nil {
		startCancel()
		return failStart(err, "prestart_check_failed")
	}
	if m.beforeStartHook != nil {
		m.beforeStartHook()
	}
	if runCtx.Err() != nil {
		startCancel()
		return failStart(ErrNativeCampaignManagerClosed, "manager_closed")
	}
	// Last authorization and DB start-permission gate, after registration and any
	// test hook. A pause/cancel committed in this window still prevents Start.
	if err := m.preStartCheck(startCtx, run, reauth.ImageID); err != nil {
		startCancel()
		return failStart(err, "prestart_check_failed")
	}
	if err := runner.Start(startCtx, start); err != nil {
		startCancel()
		return failStart(err, "runner_start_failed")
	}
	startCancel()
	// From here on the resource may have been started; finalization may win at
	// any point and is responsible for its cleanup.
	run.endStartAttempt()
	if !run.markRunning() {
		// Close/abort won the race while Start returned. Do not expose a running
		// lifecycle or start the event loop.
		m.finishRegisteredStart(run, attempt, runner, ErrNativeCampaignManagerClosed, "manager_closed")
		return ErrNativeCampaignManagerClosed
	}
	if !m.clock.Now().Before(run.deadline.ExecutionDeadline) || !m.clock.Now().Before(run.deadline.EnvelopeDeadline) {
		// Start itself overran the absolute deadline. Converge through the same
		// single-owner start-failure path instead of removing active/transport
		// independently.
		m.finishRegisteredStart(run, attempt, runner, ErrNativeCampaignStartAborted, "start_deadline_exceeded")
		return fmt.Errorf("%w: runner start exceeded the absolute deadline", ErrNativeCampaignStartAborted)
	}
	go m.runRunner(run)
	return nil
}

// finishRegisteredStart settles a start path that has already registered its
// active/transport lifecycle. Every post-registration early return must call it.
// Only the goroutine that wins beginFinalization performs Cleanup/Halt/Finalize;
// a loser merely marks local completion, so an external finalizer can never be
// erased by this path.
func (m *nativeCampaignManager) finishRegisteredStart(run *nativeCampaignRun, attempt *db.NativeCampaignAttempt, runner nativeCampaignRunner, startErr error, reason string) {
	run.cancel()
	if run.beginFinalization() {
		func() {
			defer m.finishFinalization(run)
			if runner != nil && run.getRunner() == nil {
				// A factory may return a transport together with an error. The
				// finalization owner must be able to clean that transport.
				run.setRunner(runner)
			}
			m.cancelRunner(run, reason)
			cleanup := m.cleanupRun(run)
			if err := m.finalizeStartFailure(attempt, run, cleanup, startErr); err != nil {
				run.recordFinalizationError(err)
			}
		}()
	}
	m.completeRun(run)
}

func nativeCampaignProfileNetwork(profile reverseRuntimeProfile) string {
	if value, ok := profile.Settings["network"].(string); ok && value != "" {
		return value
	}
	return "none"
}

func nativeCampaignProfileReadOnly(profile reverseRuntimeProfile) bool {
	if value, ok := profile.Settings["read_only_root"].(bool); ok {
		return value
	}
	return false
}

func (m *nativeCampaignManager) haltOwnedNoStart(attempt *db.NativeCampaignAttempt, reason string, elapsed int64) error {
	if attempt == nil {
		return errors.New("native campaign halt without an attempt")
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.stopTimeout)
	defer cancel()
	_, err := m.leases.HaltNativeCampaignAttemptForLeaseLoss(ctx, db.NativeCampaignLeaseHaltCommand{
		NativeCampaignLeaseIdentity: db.NativeCampaignLeaseIdentity{
			TaskID: attempt.TaskID, CampaignID: attempt.CampaignID, AttemptID: attempt.ID,
			FencingToken: attempt.FencingToken, LeaseOwner: attempt.LeaseOwner, LeaseInstance: attempt.LeaseInstance,
		},
		Reason: reason, ActualElapsedMS: elapsed,
	})
	if err != nil {
		m.recordCompensationFailure(attempt.ID, err)
	}
	return err
}

func (m *nativeCampaignManager) recordCompensationFailure(attemptID int64, err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	if m.compensationFailures == nil {
		m.compensationFailures = map[int64]error{}
	}
	if _, exists := m.compensationFailures[attemptID]; !exists {
		m.compensationFailures[attemptID] = err
	}
	m.mu.Unlock()
}

func (m *nativeCampaignManager) registerRun(run *nativeCampaignRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrNativeCampaignManagerClosed
	}
	if !m.started {
		return errors.New("native campaign manager is not started")
	}
	if _, exists := m.active[run.attemptID]; exists {
		return errors.New("native campaign attempt is already registered")
	}
	m.active[run.attemptID] = run
	m.transports[run] = struct{}{}
	m.wg.Add(1)
	return nil
}

// unregisterTransport removes a run from the lifecycle tracking set. It is
// called only when the overall done signal closes, never merely because Wait
// returned or the business-active map lost an entry.
func (m *nativeCampaignManager) unregisterTransport(run *nativeCampaignRun) {
	m.mu.Lock()
	delete(m.transports, run)
	m.mu.Unlock()
	run.transportOnce.Do(func() { close(run.transportDone) })
}

func (m *nativeCampaignManager) snapshotTransports() []*nativeCampaignRun {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*nativeCampaignRun, 0, len(m.transports))
	for run := range m.transports {
		out = append(out, run)
	}
	return out
}

// maybeCompleteRun closes the single overall completion signal only when all
// independent lifecycle parts have settled: the local start/runRunner goroutine,
// the Wait goroutine, and the unique finalization owner. This deliberately does
// not use "active is empty" or "Wait returned" as a shortcut.
func (m *nativeCampaignManager) maybeCompleteRun(run *nativeCampaignRun) {
	select {
	case <-run.localDone:
	default:
		return
	}
	select {
	case <-run.finalizationDone:
	default:
		return
	}
	if !run.waitSettled() {
		return
	}
	run.doneOnce.Do(func() {
		close(run.done)
		m.unregisterTransport(run)
	})
}

// completeRun marks local goroutine completion (start path or runRunner). It is
// independent of finalization: the unique owner may still be blocked in Cleanup,
// in which case done must remain open.
func (m *nativeCampaignManager) completeRun(run *nativeCampaignRun) {
	run.localOnce.Do(func() {
		close(run.localDone)
		m.wg.Done()
		m.maybeCompleteRun(run)
	})
}

// finishFinalization is invoked only by the goroutine that won
// beginFinalization. Every terminal result and the manager-wide persistence
// failure record are published before finalizationDone closes; only then is
// the overall signal re-evaluated without waiting on itself. A completion
// observer therefore happens-after both the retained failure and the release
// of active ownership, whether it first saw the run through the active map or
// through the manager-wide failure record.
func (m *nativeCampaignManager) finishFinalization(run *nativeCampaignRun) {
	run.endFinalization()
	run.cancel()
	// Record the durable-finalize/halt failure and release active ownership in
	// one manager critical section. A later Close that finds the run already
	// removed from active must still observe the retained failure, so the
	// record is written before removal and both happen before completion.
	err := run.finalizationFailure()
	m.mu.Lock()
	if err != nil {
		if m.finalizationFailures == nil {
			m.finalizationFailures = map[int64]error{}
		}
		m.finalizationFailures[run.attemptID] = err
	}
	if current, ok := m.active[run.attemptID]; ok && current == run {
		delete(m.active, run.attemptID)
	}
	m.mu.Unlock()
	run.finalizationOnce.Do(func() { close(run.finalizationDone) })
	m.maybeCompleteRun(run)
}

// preStartCheck is the last ownership gate before a runner factory/Start. It
// uses the read-only start-permission CAS (not lease renewal) so a stopping
// campaign is rejected. A renewal may legally continue while stopping; that does
// not make the attempt startable.
func (m *nativeCampaignManager) preStartCheck(ctx context.Context, run *nativeCampaignRun, imageID string) error {
	if run == nil {
		return ErrNativeCampaignStartAborted
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: start context ended before ownership check: %v", ErrNativeCampaignStartAborted, err)
	}
	now := m.clock.Now()
	if !now.Before(run.deadline.ExecutionDeadline) || !now.Before(run.deadline.EnvelopeDeadline) {
		return fmt.Errorf("%w: absolute deadline passed before start", ErrNativeCampaignStartAborted)
	}
	run.mu.Lock()
	lease := run.leaseExpires
	run.mu.Unlock()
	if !lease.IsZero() && !now.Before(lease) {
		return fmt.Errorf("%w: lease expired before start", ErrNativeCampaignStartAborted)
	}
	permission, err := m.leases.CheckNativeCampaignAttemptStart(ctx, run.identity())
	if err != nil {
		return fmt.Errorf("%w: start-permission check: %v", ErrNativeCampaignStartAborted, err)
	}
	if permission != nil && !permission.LeaseExpiresAt.IsZero() {
		run.mu.Lock()
		run.leaseExpires = permission.LeaseExpiresAt
		run.mu.Unlock()
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: start context ended during ownership check: %v", ErrNativeCampaignStartAborted, err)
	}
	if _, err := m.service.AuthorizeClaimAfterClaim(ctx, run.taskID, run.campaignID, imageID); err != nil {
		return fmt.Errorf("%w: authorization recheck: %v", ErrNativeCampaignStartAborted, err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: start context ended during authorization: %v", ErrNativeCampaignStartAborted, err)
	}
	now = m.clock.Now()
	run.mu.Lock()
	lease = run.leaseExpires
	run.mu.Unlock()
	if !now.Before(run.deadline.ExecutionDeadline) || !now.Before(run.deadline.EnvelopeDeadline) ||
		(!lease.IsZero() && !now.Before(lease)) {
		return fmt.Errorf("%w: absolute deadline or lease passed during start checks", ErrNativeCampaignStartAborted)
	}
	return nil
}

// cancelRunner asks the already-created runner to stop. Cleanup itself is the
// finalization owner's job; this helper must not be called by a loser after
// another goroutine won beginFinalization.
func (m *nativeCampaignManager) cancelRunner(run *nativeCampaignRun, reason string) {
	if run == nil {
		return
	}
	runner := run.getRunner()
	if runner == nil {
		return
	}
	controlCtx, controlCancel := context.WithTimeout(context.Background(), m.controlTimeout)
	_ = runner.Control(controlCtx, nativeCampaignRunnerControl{
		RequestID: fmt.Sprintf("%s-start-cleanup", run.expectation().RequestID),
		Action:    "cancel", Reason: reason,
	})
	controlCancel()
}

func elapsedMS(now, start time.Time) int64 {
	if start.IsZero() || now.Before(start) {
		return 0
	}
	return now.Sub(start).Milliseconds()
}

func (m *nativeCampaignManager) runRunner(run *nativeCampaignRun) {
	defer m.completeRun(run)
	type waitResult struct {
		final nativeCampaignRunnerFinal
		err   error
	}
	waitCh := make(chan waitResult, 1)
	runner := run.getRunner()
	if runner == nil {
		// Defensive: start paths only launch runRunner after a successful Start.
		// Still converge through the single finalizer instead of closing done
		// without a durable hold.
		m.abortRun(run, "runner_missing")
		return
	}
	run.mu.Lock()
	run.waitStarted = true
	run.mu.Unlock()
	go func() {
		final, err := runner.Wait(run.ctx)
		waitCh <- waitResult{final: final, err: err}
		close(run.waitDone)
		m.maybeCompleteRun(run)
	}()
	events := runner.Events()
	var pendingFinal *waitResult
	var eofTimer, eofAbortTimer, drainTimer *time.Timer
	var eofC, eofAbortC, drainC <-chan time.Time
	stopTimer := func(timer **time.Timer, ch *<-chan time.Time) {
		if *timer != nil {
			(*timer).Stop()
			*timer = nil
			*ch = nil
		}
	}
	defer func() {
		stopTimer(&eofTimer, &eofC)
		stopTimer(&eofAbortTimer, &eofAbortC)
		stopTimer(&drainTimer, &drainC)
	}()
	markProtocol := func(err error) {
		if err == nil {
			return
		}
		run.mu.Lock()
		if run.protocolErr == nil {
			run.protocolErr = err
		}
		run.mu.Unlock()
	}
	finish := func() {
		if pendingFinal == nil {
			return
		}
		m.finishRun(run, &pendingFinal.final, pendingFinal.err)
	}

	for {
		if pendingFinal != nil {
			// Wait is authoritative, but Wait success does not prove the event
			// stream is exhausted. Drain every available trailing event and
			// validate it. A runner is allowed to keep Events open after Wait;
			// the drain is bounded so it can never turn into an infinite wait.
			if events == nil {
				finish()
				return
			}
			select {
			case event, ok := <-events:
				if !ok {
					events = nil
					run.mu.Lock()
					run.eventsClosed = true
					run.mu.Unlock()
					continue
				}
				if err := m.handleEvent(run, event); err != nil {
					markProtocol(err)
				}
			case <-drainC:
				// Wait returned but Events never closed. This is NOT a complete
				// evidence stream: fail closed instead of finalizing as
				// completed/paused or presenting truncated evidence as complete.
				run.mu.Lock()
				run.drainTruncated = true
				run.drainTimedOut = true
				if run.protocolErr == nil {
					run.protocolErr = fmt.Errorf("%w: event stream did not close after final", errNativeCampaignProtocolViolation)
				}
				run.mu.Unlock()
				// Bounded cancel/cleanup path; finishRun still probes cleanup and
				// keeps the hold when cleanup is unknown.
				_ = m.requestControl(run, "cancel", "event_stream_unclosed")
				finish()
				return
			case <-run.ctx.Done():
				m.abortRun(run, "manager_stopped")
				return
			}
			continue
		}

		select {
		case event, ok := <-events:
			if !ok {
				events = nil
				run.mu.Lock()
				run.eventsClosed = true
				run.mu.Unlock()
				// Events may close before or after Wait returns. Treat close
				// before final as a bounded EOF, not an immediate protocol
				// failure: Wait may still return the terminal frame.
				if eofTimer == nil {
					eofTimer = time.NewTimer(m.eofTimeout)
					eofC = eofTimer.C
				}
				continue
			}
			if err := m.handleEvent(run, event); err != nil {
				markProtocol(err)
				if ctrlErr := m.requestControl(run, "cancel", "protocol_violation"); ctrlErr != nil {
					m.abortRun(run, "control_failed")
					return
				}
			}
		case result := <-waitCh:
			pendingFinal = &result
			run.mu.Lock()
			run.finalSeen = true
			run.mu.Unlock()
			stopTimer(&eofTimer, &eofC)
			stopTimer(&eofAbortTimer, &eofAbortC)
			if result.err != nil && events != nil {
				_ = m.requestControl(run, "cancel", "runner_wait_failed")
			}
			if events == nil {
				finish()
				return
			}
			if drainTimer == nil {
				drainTimer = time.NewTimer(m.drainTimeout)
				drainC = drainTimer.C
			}
		case <-eofC:
			eofC = nil
			eofTimer = nil
			run.mu.Lock()
			run.eofWithoutFinal = true
			if run.protocolErr == nil {
				run.protocolErr = errNativeCampaignEOFWithoutFinal
			}
			run.mu.Unlock()
			// EOF is a safe cancel, never an unbounded wait. Wait for Wait
			// within the stop timeout; if it still does not return, abort with
			// bounded cleanup and keep the hold.
			if ctrlErr := m.requestControl(run, "cancel", "protocol_eof"); ctrlErr != nil {
				m.abortRun(run, "control_failed")
				return
			}
			if eofAbortTimer == nil {
				eofAbortTimer = time.NewTimer(m.stopTimeout)
				eofAbortC = eofAbortTimer.C
			}
		case <-eofAbortC:
			m.abortRun(run, "protocol_eof")
			return
		case <-run.ctx.Done():
			m.abortRun(run, "manager_stopped")
			return
		}
	}
}

func (m *nativeCampaignManager) handleEvent(run *nativeCampaignRun, event nativeCampaignRunnerEvent) error {
	if err := event.Validate(run.expectation()); err != nil {
		return err
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	if err := run.evidence.Add(len(event.Observation)); err != nil {
		return err
	}
	return nil
}

func (r *nativeCampaignRun) getRunner() nativeCampaignRunner {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.runner
}

func (r *nativeCampaignRun) setRunner(runner nativeCampaignRunner) {
	r.mu.Lock()
	r.runner = runner
	r.mu.Unlock()
}

func (m *nativeCampaignManager) requestControl(run *nativeCampaignRun, action, reason string) error {
	run.controlMu.Lock()
	defer run.controlMu.Unlock()
	run.mu.Lock()
	desired := cancelWins(run.controlAck, action)
	if desired == "" || desired == run.controlAck {
		run.mu.Unlock()
		return nil
	}
	run.mu.Unlock()
	runner := run.getRunner()
	if runner == nil {
		// The run is registered but still inside the factory. There is no
		// transport to control yet; Close cancels run.ctx and the cooperative
		// factory/start path owns bounded cleanup.
		return nil
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		run.mu.Lock()
		run.controlPending = desired
		run.controlAttempts = attempt + 1
		run.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), m.controlTimeout)
		err := runner.Control(ctx, nativeCampaignRunnerControl{
			RequestID: fmt.Sprintf("%s-%s", run.expectation().RequestID, desired),
			Action:    desired, Reason: reason,
		})
		cancel()
		run.mu.Lock()
		run.controlPending = ""
		if err == nil {
			run.controlAck = desired
			run.controlFailed = false
			run.mu.Unlock()
			return nil
		}
		run.controlFailed = true
		run.mu.Unlock()
		lastErr = err
	}
	return fmt.Errorf("runner control %s failed after bounded retries: %w", desired, lastErr)
}

func (m *nativeCampaignManager) monitorRun(ctx context.Context, run *nativeCampaignRun) error {
	run.mu.Lock()
	deadlineReached := run.deadlineReached
	deadlineAcked := run.deadlineStop
	run.mu.Unlock()
	now := m.clock.Now()
	if !deadlineReached {
		reason := ""
		if !now.Before(run.deadline.ExecutionDeadline) {
			reason = "execution_deadline"
		} else if !now.Before(run.deadline.EnvelopeDeadline) {
			reason = "envelope_deadline"
		}
		if reason != "" {
			run.mu.Lock()
			run.deadlineReached = true
			run.mu.Unlock()
			deadlineReached = true
			if err := m.requestControl(run, "cancel", reason); err != nil {
				m.safeAbortRun(run, "control_failed")
				return err
			}
			run.mu.Lock()
			run.deadlineStop = true
			run.mu.Unlock()
			deadlineAcked = true
		}
	} else if !deadlineAcked {
		if err := m.requestControl(run, "cancel", "execution_deadline"); err != nil {
			m.safeAbortRun(run, "control_failed")
			return err
		}
		run.mu.Lock()
		run.deadlineStop = true
		run.mu.Unlock()
	}
	signal, err := m.service.MonitorCampaign(ctx, run.taskID, run.campaignID, run.operatorKind, run.operatorID)
	if err != nil {
		return err
	}
	switch signal.Action {
	case "pause", "cancel":
		if err := m.transitionCampaign(ctx, run, signal.Action, signal.Reason); err != nil {
			m.safeAbortRun(run, "campaign_transition_failed")
			return err
		}
		run.mu.Lock()
		confirmed := run.requestedState
		run.mu.Unlock()
		if confirmed == "" {
			// The database reached a terminal state first (pause/cancel lost the
			// race). Do not send a control frame that was never confirmed.
			return nil
		}
		if err := m.requestControl(run, confirmed, signal.Reason); err != nil {
			m.safeAbortRun(run, "control_failed")
			return err
		}
	}
	return nil
}

// safeAbortRun stops the owned runner and records an unconfirmed hold. It is
// used when a bounded control/transition retry is exhausted.
func (m *nativeCampaignManager) safeAbortRun(run *nativeCampaignRun, reason string) {
	_ = m.requestControl(run, "cancel", reason)
	m.abortRun(run, reason)
}

func nativeCampaignControlPriority(state, desired string) int {
	switch state {
	case "cancelled":
		return 2
	case "paused":
		return 1
	case "completed", "failed", "interrupted":
		// A terminal fact is not a successful pause/cancel. The caller records a
		// lost race instead of acknowledging a control the database never took.
		return 0
	}
	if desired == "cancelled" {
		return 2
	}
	if desired == "paused" {
		return 1
	}
	return 0
}

func nativeCampaignControlAction(priority int) string {
	if priority >= 2 {
		return "cancel"
	}
	if priority >= 1 {
		return "pause"
	}
	return ""
}

// transitionCampaign exists to make pause/cancel durable before the runner is
// told to act. It distinguishes a pending request from a database-confirmed
// priority: the runner control frame is only acknowledged when the persisted
// campaign actually reached pause/cancel priority. A CAS conflict is re-read and
// retried with a fresh request_id so a cached 4xx idempotency row from an older
// state_version cannot poison the retry.
func (m *nativeCampaignManager) transitionCampaign(ctx context.Context, run *nativeCampaignRun, action, reason string) error {
	run.mu.Lock()
	desired := cancelWins(run.requestedState, action)
	alreadyConfirmed := run.requestedConfirmed && run.requestedState == desired
	run.mu.Unlock()
	if desired == "" || alreadyConfirmed {
		return nil
	}
	targetPriority := 1
	if desired == "cancel" {
		targetPriority = 2
	}
	clearPending := func() {
		run.mu.Lock()
		run.statePending = ""
		run.mu.Unlock()
	}
	confirm := func(priority int) {
		confirmedAction := nativeCampaignControlAction(priority)
		run.mu.Lock()
		run.requestedState = cancelWins(run.requestedState, confirmedAction)
		run.requestedConfirmed = true
		run.statePending = ""
		run.mu.Unlock()
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		run.mu.Lock()
		run.statePending = desired
		run.stateAttempts = attempt + 1
		run.mu.Unlock()
		campaign, err := m.service.loadCampaign(ctx, run.taskID, run.campaignID)
		if err != nil {
			lastErr = err
			continue
		}
		priority := nativeCampaignControlPriority(campaign.State, campaign.DesiredState)
		if priority >= targetPriority {
			confirm(priority)
			return nil
		}
		if db.IsTerminal(campaign.State) {
			// completed/failed/interrupted while a pause/cancel was pending: the
			// terminal fact wins. Never ACK a control that the DB did not reach.
			if campaign.State == "cancelled" {
				confirm(2)
			} else {
				clearPending()
			}
			return nil
		}
		requestID := fmt.Sprintf("%s-%s-r%d-%d", run.expectation().RequestID, desired, attempt, m.clock.Now().UnixNano())
		switch desired {
		case "pause":
			_, err = m.service.Pause(ctx, run.taskID, run.campaignID, reason, requestID)
		case "cancel":
			_, err = m.service.Cancel(ctx, run.taskID, run.campaignID, reason, requestID)
		default:
			err = errors.New("unsupported campaign transition")
		}
		clearPending()
		if err != nil {
			lastErr = err
			code := db.NativeCampaignErrorCode(err)
			if code == "terminal_campaign" {
				actual, loadErr := m.service.loadCampaign(ctx, run.taskID, run.campaignID)
				if loadErr == nil && db.IsTerminal(actual.State) {
					if actual.State == "cancelled" {
						confirm(2)
					}
					return nil
				}
			}
			// state_conflict, idempotency_conflict, request_in_progress,
			// cancel_in_progress and transient errors all get a bounded retry
			// with a fresh request_id and a freshly read state_version.
			continue
		}
		// The mutation API returning 2xx only means the request was committed.
		// Re-read the row and require the actual persisted priority before ACK.
		actual, loadErr := m.service.loadCampaign(ctx, run.taskID, run.campaignID)
		if loadErr != nil {
			lastErr = loadErr
			continue
		}
		actualPriority := nativeCampaignControlPriority(actual.State, actual.DesiredState)
		if actualPriority >= targetPriority {
			confirm(actualPriority)
			return nil
		}
		if db.IsTerminal(actual.State) {
			if actual.State == "cancelled" {
				confirm(2)
			}
			return nil
		}
		lastErr = fmt.Errorf("campaign has not reached %s priority yet", desired)
	}
	if lastErr == nil {
		lastErr = errors.New("campaign transition failed")
	}
	run.mu.Lock()
	run.stateLastError = nativeCampaignErrorMessage(lastErr)
	run.mu.Unlock()
	return fmt.Errorf("campaign %s transition failed after bounded retries: %w", desired, lastErr)
}

func (m *nativeCampaignManager) finishRun(run *nativeCampaignRun, final *nativeCampaignRunnerFinal, waitErr error) {
	if !run.beginFinalization() {
		// Another finalizer owns Cleanup/Halt/Finalize. Do not remove active,
		// mark finalized, or close the overall lifecycle signal from here.
		return
	}
	defer m.finishFinalization(run)
	run.awaitResourceHandoff()
	if final != nil {
		if raw, err := json.Marshal(final); err == nil {
			run.mu.Lock()
			if err := run.evidence.Add(len(raw)); err != nil && run.protocolErr == nil {
				run.protocolErr = err
			}
			run.mu.Unlock()
		}
	}
	run.mu.Lock()
	protocolErr := run.protocolErr
	deadlineStop := run.deadlineStop
	leaseLost := run.leaseLost
	leaseLostReason := run.leaseLostReason
	evidenceTotal := run.evidence.Total()
	run.mu.Unlock()

	// A reaped abnormal process is a lost worker, not an invalid zero final.
	// Only the derived EOF symptom may be superseded; real protocol/evidence
	// errors retain precedence. No final or cleanup claim from this exit can
	// authorize release of resources.
	processLost := errors.Is(waitErr, errNativeCampaignProcessAbnormalExit) && (protocolErr == nil || protocolErr == errNativeCampaignEOFWithoutFinal)
	if processLost {
		protocolErr = nil
		final = nil
	}
	sealedMode := nativeCampaignRequiresSealedCleanup(run.attempt.OwnedResources)
	finalizeCtx := context.Background()
	finalResources := append(json.RawMessage(nil), run.attempt.OwnedResources...)
	if sealedMode {
		run.mu.Lock()
		leaseEnd := run.leaseExpires
		run.mu.Unlock()
		end := time.Now().Add(m.cleanupTimeout)
		for _, bound := range []time.Time{leaseEnd, run.deadline.EnvelopeDeadline} {
			if bound.Before(end) {
				end = bound
			}
		}
		var cancel context.CancelFunc
		finalizeCtx, cancel = context.WithDeadline(m.ctx, end)
		defer cancel()
	}
	var creationSeal json.RawMessage
	if final != nil && final.CreationSeal != nil && waitErr == nil && protocolErr == nil && !leaseLost {
		plan, err := nativeCampaignPlanFromResources(run.attempt.OwnedResources)
		if err == nil {
			err = final.Validate(run.expectation())
		}
		if err == nil {
			err = plan.validate(run.taskID, run.campaignID, run.attemptID, run.fencingToken)
		}
		if err == nil {
			err = final.CreationSeal.validate(plan)
		}
		if err != nil {
			protocolErr = err
		} else {
			creationSeal, _ = json.Marshal(final.CreationSeal)
		}
	}
	var cleanup *nativeCampaignCleanupReport
	cleanupStatus := "unknown"
	if sealedMode {
		// Cleanup verification is an observation about owned resources, not a claim
		// about the run outcome: a lost final frame or a protocol error must not turn a
		// fully verified cleanup into "unknown", because that keeps the single global
		// worker slot held without any operator path to release it.
		if len(creationSeal) > 0 && !leaseLost {
			snapshot, err := m.pg.SealNativeCampaignAttemptCreation(finalizeCtx, m.service.systemAuthorizer, run.identity(), finalResources, creationSeal)
			if err != nil {
				if protocolErr == nil {
					protocolErr = err
				}
			} else {
				finalResources = append(json.RawMessage(nil), snapshot.OwnedResources...)
				// A returned DB lease may shorten, never extend, the single cutoff.
				var cancel context.CancelFunc
				finalizeCtx, cancel = context.WithDeadline(finalizeCtx, snapshot.LeaseExpiresAt)
				defer cancel()
				cleanup, err = m.cleanupSealedFinal(finalizeCtx, run, snapshot)
				if err == nil && cleanup != nil && finalizeCtx.Err() == nil {
					cleanupStatus = "verified"
				}
			}
		}
	} else if !processLost {
		cleanup = m.cleanupRun(run)
		if cleanup != nil && cleanup.verified() && !leaseLost {
			cleanupStatus = "verified"
		}
	}
	// Trusted elapsed includes cleanup. It is re-sampled after checkpoint and
	// evidence sinks below; runner self-reported elapsed is never used.
	elapsed := elapsedMS(m.clock.Now(), run.startedMono)
	target := "failed"
	reason := "runner_wait_failed"
	if processLost {
		target, reason = "interrupted", "process_lost"
	}
	if reason != "completed" {
		// Surface the runner's own message when an attempt does not complete: without
		// it a stalled launch is indistinguishable from a rejected one. The wire hides
		// runner text from the ledger by design, so the log is the only operator view.
		if final != nil && len(final.Errors) > 0 {
			log.Printf("[native campaign] attempt %d (campaign %d) runner errors: %v", run.attemptID, run.campaignID, final.Errors)
		}
		if d, ok := run.runner.(interface{ Diagnostics() string }); ok && d != nil {
			if tail := d.Diagnostics(); tail != "" {
				log.Printf("[native campaign] attempt %d (campaign %d) ended %s: %s", run.attemptID, run.campaignID, reason, tail)
			}
		}
	}
	var checkpointID *int64
	if final != nil {
		if err := final.Validate(run.expectation()); err != nil {
			if protocolErr == nil {
				protocolErr = err
			}
		} else if waitErr == nil && protocolErr == nil {
			switch final.TargetState {
			case "completed":
				target, reason = "completed", "completed"
			case "paused":
				target, reason = "paused", "paused"
			case "cancelled":
				target, reason = "cancelled", "cancelled"
			case "interrupted":
				target, reason = "interrupted", "interrupted"
			case "timeout":
				if deadlineStop || elapsed >= run.plan.ExecutionWindowMS {
					target, reason = "completed", "budget_exhausted"
				} else {
					target, reason = "failed", "timeout"
				}
			case "failed":
				target, reason = "failed", "failed"
			}
			if final.Reason != "" {
				reason = final.Reason
			}
			if deadlineStop && (final.TargetState == "cancelled" || final.TargetState == "timeout") {
				target, reason = "completed", "budget_exhausted"
			}
		} else if protocolErr != nil {
			target, reason = "failed", "protocol_violation"
		}
	} else if protocolErr != nil {
		target, reason = "failed", "protocol_violation"
	}
	if run.ctx.Err() != nil && waitErr != nil {
		target, reason = "interrupted", "manager_stopped"
	}
	if leaseLost {
		target = "interrupted"
		if leaseLostReason != "" {
			reason = leaseLostReason
		}
	}
	// A normal/paused/cancelled final requires confirmed cleanup and a valid
	// persisted evidence record; otherwise it is conservatively failed with the
	// hold retained.
	if (target == "paused" || target == "completed" || target == "cancelled") && cleanupStatus != "verified" {
		target, reason = "failed", "cleanup_unknown"
	}
	if target == "paused" {
		if final == nil || final.Checkpoint == nil {
			target, reason = "failed", "checkpoint_missing"
		} else if m.service.checkpointSink == nil {
			target, reason = "failed", "checkpoint_sink_missing"
		} else {
			cpCtx, cpCancel := context.WithTimeout(finalizeCtx, m.stopTimeout)
			cp, err := m.service.checkpointSink.PersistCheckpoint(cpCtx, nativeCampaignCheckpointWrite{
				TaskID: run.taskID, CampaignID: run.campaignID, AttemptID: run.attemptID,
				Final: *final.Checkpoint, Identity: run.identity(), Corpus: final.CheckpointCorpus,
			})
			cpCancel()
			if err != nil || cp == nil || cp.State != "verified" || cp.CampaignID != run.campaignID ||
				cp.AttemptID != run.attemptID {
				target, reason = "failed", "checkpoint_unverified"
				if db.NativeCampaignErrorCode(err) == "quota_exceeded" {
					reason = "quota_exceeded"
				}
			} else {
				checkpointID = &cp.ID
			}
		}
	}
	// Include checkpoint persistence before building the evidence observation.
	elapsed = elapsedMS(m.clock.Now(), run.startedMono)
	finalLost := waitErr != nil || protocolErr != nil
	observation := nativeCampaignFinalObservation(run, final, target, reason, elapsed, finalLost, evidenceTotal, cleanup)
	evidenceInput, evidenceErr := m.persistFinalEvidenceContext(finalizeCtx, run, observation)
	if evidenceErr != nil {
		// Fail closed: no evidence => no paused/completed final. Keep the hold.
		// A successful conservative Halt does not make the failed evidence/final
		// persistence successful. Close must retain the original failure too.
		run.recordFinalizationError(evidenceErr)
		elapsed = elapsedMS(m.clock.Now(), run.startedMono)
		if haltErr := m.haltOwnedNoStart(run.attempt, "evidence_sink_failed", elapsed); haltErr != nil {
			run.recordFinalizationError(haltErr)
		}
		return
	}
	// Final settlement includes cleanup, checkpoint and evidence sink delays.
	settlementElapsed := elapsedMS(m.clock.Now(), run.startedMono)
	cleanupMS := int64(0)
	if cleanup != nil {
		cleanupMS = cleanup.ElapsedMS
	}
	cmd := db.NativeCampaignFinalizeCommand{
		TaskID: run.taskID, CampaignID: run.campaignID, AttemptID: run.attemptID,
		FencingToken: run.fencingToken, LeaseOwner: run.leaseOwner, LeaseInstance: run.leaseInstance,
		TargetState: target, Phase: "finalize", CleanupStatus: cleanupStatus,
		CheckpointID: checkpointID, EvidenceInput: evidenceInput,
		TerminationReason: truncateNativeCampaignReason(reason),
		ErrorCode:         nativeCampaignErrorCode(target, reason), ErrorMessage: nativeCampaignErrorMessage(protocolErr),
		ActualElapsedMS: settlementElapsed, CleanupElapsedMS: cleanupMS,
		CleanupReserveMS: run.plan.CleanupReserveMS,
		FinalLost:        finalLost, BudgetOverrun: settlementElapsed > run.plan.ReservedBudgetMS || deadlineStop,
		ActorKind: "admin",
	}
	if len(creationSeal) > 0 && !finalLost {
		cmd.CreationSeal = creationSeal
		cmd.ExpectedOwnedResources = append(json.RawMessage(nil), finalResources...)
	}
	finCtx, finCancel := context.WithTimeout(finalizeCtx, m.stopTimeout)
	defer finCancel()
	if _, err := m.service.Finalize(finCtx, cmd); err != nil {
		run.recordFinalizationError(err)
		if haltErr := m.haltOwnedNoStart(run.attempt, "finalize_failed", settlementElapsed); haltErr != nil {
			run.recordFinalizationError(haltErr)
		}
	}
}

// finalizeStartFailure is called only by the current finalization owner. A
// verified cleanup permits a normal failed finalization; anything unknown keeps
// the durable interrupted/cleanup_unknown hold.
func (m *nativeCampaignManager) finalizeStartFailure(attempt *db.NativeCampaignAttempt, run *nativeCampaignRun, cleanup *nativeCampaignCleanupReport, startErr error) error {
	cleanupStatus := "unknown"
	if cleanup != nil && cleanup.verified() {
		cleanupStatus = "verified"
	}
	if nativeCampaignRequiresSealedCleanup(attempt.OwnedResources) {
		cleanupStatus = "unknown"
	}
	elapsed := elapsedMS(m.clock.Now(), run.startedMono)
	reason := "runner_start_failed"
	var operationErr error
	if cleanupStatus == "verified" && m.service.storage != nil {
		func() {
			opCtx, opCancel := context.WithTimeout(context.Background(), m.stopTimeout)
			defer opCancel()
			obs, _ := json.Marshal(map[string]any{
				"operation": "native_campaign", "authority": "candidate-only",
				"target_state": "failed", "reason": reason, "attempt_id": attempt.ID,
				"fencing_token": attempt.FencingToken, "actual_elapsed_ms": elapsed,
				"cleanup_status": cleanupStatus, "start_error": nativeCampaignErrorMessage(startErr),
			})
			evidenceInput, err := m.persistFinalEvidenceContext(opCtx, run, obs)
			if err == nil {
				settlementElapsed := elapsedMS(m.clock.Now(), run.startedMono)
				_, operationErr = m.service.Finalize(opCtx, db.NativeCampaignFinalizeCommand{TaskID: attempt.TaskID, CampaignID: attempt.CampaignID, AttemptID: attempt.ID, FencingToken: attempt.FencingToken, LeaseOwner: attempt.LeaseOwner, LeaseInstance: attempt.LeaseInstance, TargetState: "failed", Phase: "finalize", CleanupStatus: cleanupStatus, EvidenceInput: evidenceInput, TerminationReason: reason, ErrorCode: "start_failed", ActualElapsedMS: settlementElapsed, CleanupReserveMS: run.plan.CleanupReserveMS, FinalLost: true, ActorKind: "admin"})
				return
			}
			operationErr = errors.New("start-failure evidence could not be persisted")
		}()
		if operationErr == nil {
			return nil
		}
	}
	haltErr := m.haltOwnedNoStart(attempt, reason, elapsedMS(m.clock.Now(), run.startedMono))
	if haltErr != nil {
		if operationErr != nil {
			return fmt.Errorf("%v; halt: %w", operationErr, haltErr)
		}
		return haltErr
	}
	return operationErr
}

func nativeCampaignErrorCode(target, reason string) string {
	if target == "failed" && reason == "quota_exceeded" {
		return "quota_exceeded"
	}
	if target == "failed" && reason == "protocol_violation" {
		return "protocol_violation"
	}
	if target == "interrupted" && reason == "process_lost" {
		return "process_lost"
	}
	if target == "interrupted" {
		return "lease_lost"
	}
	if target == "failed" {
		return "campaign_failed"
	}
	return ""
}

func nativeCampaignErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

func truncateNativeCampaignReason(reason string) string {
	if len(reason) > 128 {
		return reason[:128]
	}
	if reason == "" {
		return "finalized"
	}
	return reason
}

func (m *nativeCampaignManager) persistFinalEvidenceContext(parent context.Context, run *nativeCampaignRun, observation json.RawMessage) (*db.NativeCampaignEvidenceInput, error) {
	if m.service.storage == nil {
		return nil, errors.New("evidence sink is not configured")
	}
	if len(observation) == 0 || len(observation) > 256<<10 {
		return nil, errors.New("evidence observation is empty or too large")
	}
	ctx, cancel := context.WithTimeout(parent, m.stopTimeout)
	defer cancel()
	ref, err := m.service.storage.PersistEvidence(ctx, nativeCampaignEvidenceWrite{TaskID: run.taskID, CampaignID: run.campaignID, AttemptID: run.attemptID, Kind: "attempt_final", Operation: "native_campaign", Authority: "candidate-only", Observation: observation})
	if err != nil || ref == nil {
		return nil, errors.New("evidence sink failed")
	}
	return &db.NativeCampaignEvidenceInput{TaskID: run.taskID, CampaignID: run.campaignID, AttemptID: run.attemptID, Kind: "attempt_final", ResultPath: ref.ResultPath, SHA256: ref.SHA256, Observation: append(json.RawMessage(nil), ref.Observation...), Truncated: ref.Truncated}, nil
}

func nativeCampaignFinalObservation(run *nativeCampaignRun, final *nativeCampaignRunnerFinal, target, reason string, elapsed int64, finalLost bool, evidenceTotal int64, cleanup *nativeCampaignCleanupReport) json.RawMessage {
	run.mu.Lock()
	eventsClosed := run.eventsClosed
	eofWithoutFinal := run.eofWithoutFinal
	drainTruncated := run.drainTruncated
	drainTimedOut := run.drainTimedOut
	transitionAttempts := run.stateAttempts
	transitionError := run.stateLastError
	run.mu.Unlock()
	value := map[string]any{
		"operation": "native_campaign", "authority": "candidate-only",
		"target_state": target, "reason": reason, "attempt_id": run.attemptID,
		"campaign_id": run.campaignID, "fencing_token": run.fencingToken,
		"actual_elapsed_ms": elapsed, "final_lost": finalLost,
		"evidence_frames_bytes":  evidenceTotal,
		"events_closed":          eventsClosed,
		"eof_without_final":      eofWithoutFinal,
		"drain_truncated":        drainTruncated,
		"drain_timed_out":        drainTimedOut,
		"transition_attempts":    transitionAttempts,
		"transition_error":       transitionError,
		"execution_deadline":     run.deadline.ExecutionDeadline.UTC().Format(time.RFC3339Nano),
		"envelope_deadline":      run.deadline.EnvelopeDeadline.UTC().Format(time.RFC3339Nano),
		"observed_execs_trusted": false,
	}
	if run.resume != nil {
		value["resume"] = run.resume
	}
	if final != nil {
		value["final_target_state"] = final.TargetState
		value["cleanup_verified"] = final.CleanupVerified
		value["cleanup"] = final.Cleanup
		value["observed_execs"] = final.Budget.ObservedExecs
		value["runner_reported_elapsed_ms"] = final.Budget.ActualElapsedMS
		value["manifest"] = final.Manifest
	}
	if cleanup != nil {
		value["cleanup_probe"] = cleanup
	}
	raw, _ := json.Marshal(value)
	if len(raw) > 256<<10 {
		delete(value, "manifest")
		if final != nil {
			value["stats"] = nil
			value["errors"] = final.Errors
		}
		value["truncated"] = true
		raw, _ = json.Marshal(value)
	}
	if len(raw) > 256<<10 {
		minimal := map[string]any{
			"operation": "native_campaign", "authority": "candidate-only",
			"target_state": target, "reason": reason, "attempt_id": run.attemptID,
			"actual_elapsed_ms": elapsed, "final_lost": finalLost,
			"evidence_frames_bytes": evidenceTotal, "truncated": true,
		}
		if run.resume != nil {
			minimal["resume"] = run.resume
		}
		raw, _ = json.Marshal(minimal)
	}
	return raw
}

func (m *nativeCampaignManager) cleanupRun(run *nativeCampaignRun) *nativeCampaignCleanupReport {
	runner := run.getRunner()
	if runner == nil {
		return nil
	}
	started := m.clock.Now()
	ctx, cancel := context.WithTimeout(context.Background(), m.cleanupTimeout)
	defer cancel()
	report, err := runner.Cleanup(ctx, nativeCampaignCleanupRequest{
		RequestID: fmt.Sprintf("cleanup-%d-%d", run.campaignID, run.attemptID),
		TaskID:    run.taskID, CampaignID: run.campaignID, AttemptID: run.attemptID,
		FencingToken: run.fencingToken,
	})
	if err != nil {
		return nil
	}
	report.ElapsedMS = elapsedMS(m.clock.Now(), started)
	return &report
}

func (m *nativeCampaignManager) stopLeaseLost(run *nativeCampaignRun, reason string) error {
	run.mu.Lock()
	run.leaseLost = true
	run.leaseLostReason = reason
	run.mu.Unlock()
	// Stop this manager's runner only. No external process is killed.
	_ = m.requestControl(run, "cancel", reason)
	run.cancel()
	timeout := time.NewTimer(m.stopTimeout)
	defer timeout.Stop()
	select {
	case <-run.finalizationDone:
	case <-timeout.C:
		m.abortRun(run, reason)
	}
	return nil
}

func (m *nativeCampaignManager) abortRun(run *nativeCampaignRun, reason string) {
	if !run.beginFinalization() {
		run.mu.Lock()
		run.abortRequested = true
		run.mu.Unlock()
		run.cancel()
		return
	}
	defer m.finishFinalization(run)
	run.awaitResourceHandoff()
	runner := run.getRunner()
	if runner != nil {
		ctx, cancel := context.WithTimeout(context.Background(), m.controlTimeout)
		_ = runner.Control(ctx, nativeCampaignRunnerControl{
			RequestID: fmt.Sprintf("%s-abort", run.expectation().RequestID),
			Action:    "cancel", Reason: reason,
		})
		cancel()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), m.cleanupTimeout)
		_, _ = runner.Cleanup(cleanupCtx, nativeCampaignCleanupRequest{
			RequestID: fmt.Sprintf("cleanup-%d-%d", run.campaignID, run.attemptID),
			TaskID:    run.taskID, CampaignID: run.campaignID, AttemptID: run.attemptID,
			FencingToken: run.fencingToken,
		})
		cleanupCancel()
	}
	elapsed := elapsedMS(m.clock.Now(), run.startedMono)
	ctx, cancel := context.WithTimeout(context.Background(), m.stopTimeout)
	defer cancel()
	_, haltErr := m.leases.HaltNativeCampaignAttemptForLeaseLoss(ctx, db.NativeCampaignLeaseHaltCommand{
		NativeCampaignLeaseIdentity: run.identity(),
		Reason:                      reason, ActualElapsedMS: elapsed,
	})
	if haltErr != nil {
		run.mu.Lock()
		run.haltErr = haltErr
		run.mu.Unlock()
		run.recordFinalizationError(haltErr)
	}
}

// ActiveCount is used by deterministic tests and diagnostics.
func (m *nativeCampaignManager) ActiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.active)
}

// NeedsReconciliation reports whether Start refused scheduling due to residual
// active/unknown holds.
func (m *nativeCampaignManager) NeedsReconciliation() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.needsReconcile
}

// Close cancels and waits only for this manager's own tasks. It never kills a
// process or another service. A second concurrent Close waits for the first
// Close's shared completion channel and returns the same result instead of
// reporting premature success. Every wait in one Close uses the same absolute
// deadline: the earlier of the caller's deadline and now+StopTimeout. Segment
// timeouts are never restarted or summed. If a run's full lifecycle (local
// goroutines, Wait/events and the unique finalizer) has not settled, Close
// returns an explicit error and the DB hold remains retained.
func (m *nativeCampaignManager) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		done := m.closeDone
		m.mu.Unlock()
		return m.awaitClose(ctx, done)
	}
	m.closed = true
	started := m.started
	background := m.background
	cancel := m.cancel
	opsDone := m.opsDone
	m.mu.Unlock()
	// One absolute deadline for the whole close, computed before any operation
	// that could block. StopTimeout is the single configured upper bound; the
	// caller's deadline can only shorten it.
	cutoff := time.Now().Add(m.stopTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(cutoff) {
		cutoff = callerDeadline
	}
	if cancel != nil {
		cancel()
	}
	// Canceling the manager context cancels every run context; each run's own
	// goroutine/finalizer sends its bounded control frame. Close does not issue
	// an unbounded extra Control call before starting its deadline clock.
	var closeErr error
	timeoutCh := make(chan struct{})
	timer := time.AfterFunc(time.Until(cutoff), func() { close(timeoutCh) })
	defer timer.Stop()

	// Wait for operations that were admitted before closed was set. This covers
	// the claim -> MarkStarted -> compensation-Halt window before any run is
	// registered. No new operation can begin after the closed flag above.
	opsTimedOut := false
	select {
	case <-opsDone:
	case <-timeoutCh:
		opsTimedOut = true
	case <-ctx.Done():
		opsTimedOut = true
	}
	if opsTimedOut {
		select {
		case <-opsDone:
			opsTimedOut = false
		default:
		}
	}
	// Snapshot lifecycle tracking only after admitted operations have settled,
	// so a run registered by an in-flight Step cannot be missed.
	m.mu.Lock()
	runs := make([]*nativeCampaignRun, 0, len(m.transports))
	seen := make(map[*nativeCampaignRun]struct{}, len(m.transports))
	for run := range m.transports {
		runs = append(runs, run)
		seen[run] = struct{}{}
	}
	for _, run := range m.active {
		if _, exists := seen[run]; !exists {
			runs = append(runs, run)
			seen[run] = struct{}{}
		}
	}
	m.mu.Unlock()

	settled := make([]bool, len(runs))
	timedOut := false
	if !opsTimedOut {
		for i, run := range runs {
			select {
			case <-run.done:
				settled[i] = true
				continue
			default:
			}
			select {
			case <-run.done:
				settled[i] = true
			case <-timeoutCh:
				timedOut = true
			case <-ctx.Done():
				timedOut = true
			}
			if timedOut {
				break
			}
		}
		// If the deadline fired at the same instant the final run completed,
		// prefer the observed completion instead of a spurious timeout.
		if timedOut {
			allSettled := true
			for i, run := range runs {
				if settled[i] {
					continue
				}
				select {
				case <-run.done:
					settled[i] = true
				default:
					allSettled = false
				}
			}
			if allSettled {
				timedOut = false
			}
		}
	}
	// The scheduler loop (when one was launched) is part of overall lifecycle
	// completion too. run.done already covers every run's local goroutine.
	if !opsTimedOut && !timedOut && started && background {
		select {
		case <-m.loopDone:
		case <-timeoutCh:
			timedOut = true
		case <-ctx.Done():
			timedOut = true
		}
		if timedOut {
			select {
			case <-m.loopDone:
				timedOut = false
			default:
			}
		}
	}
	unfinished := make([]int64, 0)
	for i, run := range runs {
		if !settled[i] {
			unfinished = append(unfinished, run.attemptID)
		}
	}
	if opsTimedOut || timedOut || len(unfinished) > 0 {
		closeErr = &nativeCampaignCloseTimeoutError{AttemptIDs: unfinished, Active: len(unfinished)}
	} else {
		for _, run := range runs {
			if err := run.finalizationFailure(); err != nil {
				// The unique finalizer finished, but its terminal/failed state
				// could not be durably persisted. Never report a clean close.
				closeErr = fmt.Errorf("%w: finalization persistence failed: %v", ErrNativeCampaignCloseTimeout, err)
				break
			}
			run.mu.Lock()
			haltErr := run.haltErr
			run.mu.Unlock()
			if haltErr != nil {
				closeErr = fmt.Errorf("%w: halt failed during close: %v", ErrNativeCampaignCloseTimeout, haltErr)
				break
			}
		}
	}
	if closeErr == nil {
		m.mu.Lock()
		for attemptID, compensationErr := range m.compensationFailures {
			closeErr = fmt.Errorf("%w: claim compensation failed for attempt %d: %v", ErrNativeCampaignCloseTimeout, attemptID, compensationErr)
			break
		}
		m.mu.Unlock()
	}
	// A run may have completed and been removed from tracking before this Close
	// observed it. Persisted-halt/Finalize failures are retained manager-wide so
	// a later Close cannot report a clean shutdown after such a failure.
	if closeErr == nil {
		m.mu.Lock()
		for attemptID, finalizeErr := range m.finalizationFailures {
			closeErr = fmt.Errorf("%w: finalization persistence failed for attempt %d: %v", ErrNativeCampaignCloseTimeout, attemptID, finalizeErr)
			break
		}
		m.mu.Unlock()
	}
	m.mu.Lock()
	m.closeErr = closeErr
	m.mu.Unlock()
	close(m.closeDone)
	return closeErr
}

// awaitClose waits for the first Close result. It never returns nil just because
// another goroutine is still closing: a canceled caller gets an explicit
// bounded-close error and the resource hold remains owned by the first closer.
func (m *nativeCampaignManager) awaitClose(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		m.mu.Lock()
		err := m.closeErr
		m.mu.Unlock()
		return err
	case <-ctx.Done():
		return &nativeCampaignCloseTimeoutError{}
	}
}
