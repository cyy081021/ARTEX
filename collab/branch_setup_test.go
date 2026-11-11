package collab

import (
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestValidateBranchPolicyDeviceRoleBounds(t *testing.T) {
	p := branchTestProject().Policy
	p.DeviceRoles = map[string]map[string][]string{
		"11": {"planner": {}, "worker": {"inspect"}, "reviewer": {"read_material"}},
	}
	if err := ValidateBranchPolicy(p); err != nil {
		t.Fatalf("valid device bindings rejected: %v", err)
	}
	invalid := []map[string]map[string][]string{
		{"0": {"worker": {"inspect"}}},
		{"11": {}},
		{"11": {"unknown": {}}},
		{"11": {"worker": {"outside-policy"}}},
		{"11": {"planner": {"inspect"}}},
	}
	for _, binding := range invalid {
		p.DeviceRoles = binding
		if err := ValidateBranchPolicy(p); err == nil {
			t.Fatalf("invalid device binding accepted: %+v", binding)
		}
	}
	p.DeviceRoles = nil
	if err := ValidateBranchPolicy(p); err != nil {
		t.Fatalf("legacy policy changed behavior: %v", err)
	}
}

func TestBranchSetupDeviceRolesSeparateHeterogeneousCapabilities(t *testing.T) {
	p := branchTestProject()
	p.Policy.Roles["worker"] = ExecutionConfig{Version: 1, Kind: "pentest", Role: "worker", SystemPrompt: "work", BudgetSeconds: 60, Capabilities: []string{"read_material", "inspect", "inspect_other"}}
	p.Policy.DeviceRoles = map[string]map[string][]string{
		"11": {"planner": {}, "worker": {"inspect", "read_material"}, "reviewer": {"read_material"}},
		"12": {"planner": {}, "worker": {"inspect_other", "read_material"}, "reviewer": {"read_material"}},
	}
	admin := BranchActor{Admin: true}
	for i := 1; i <= 2; i++ {
		work := BranchWorkSpec{Title: "heterogeneous-" + strconv.Itoa(i), Question: "inspect fixture " + strconv.Itoa(i), Kind: "pentest", Roles: []string{"worker"}, Budget: 4}
		branchDo(t, &p, admin, BranchCommand{Type: "publish", RequestID: "hetero-publish-" + strconv.Itoa(i), Work: &work})
	}
	devices := map[int64]BranchDevice{
		11: {ID: 11, OwnerID: 7, Active: true, Online: true, Protocol: BranchProtocol, Roles: []string{"planner", "worker", "reviewer"}, RoleCapabilities: map[string][]string{"worker": {"inspect"}}},
		12: {ID: 12, OwnerID: 7, Active: true, Online: true, Protocol: BranchProtocol, Roles: []string{"planner", "worker", "reviewer"}, RoleCapabilities: map[string][]string{"worker": {"inspect_other"}}},
	}
	for i, deviceID := range []int64{11, 12} {
		member := BranchActor{MemberID: 7, Devices: devices}
		if ok := deviceMatchesBranchPolicy(p.Policy, BranchWorkSpec{Kind: "pentest", Roles: []string{"worker"}}, deviceID); !ok {
			t.Fatalf("device %d does not satisfy its binding: %+v", deviceID, p.Policy.DeviceRoles[strconv.FormatInt(deviceID, 10)])
		}
		if _, ok := selectBranchDevice(p.Policy, member, p.Pool[i].Spec, 7, deviceID); !ok {
			t.Fatalf("device %d not selected, roles=%v, work=%+v", deviceID, devices[deviceID].Roles, p.Pool[i].Spec)
		}
		claim, _, err := ApplyBranchCommand(&p, member, BranchCommand{Type: "claim", RequestID: "hetero-claim-" + strconv.Itoa(i), WorkID: int64(i + 1), DeviceID: deviceID}, testTime())
		if err != nil || claim.BranchID == 0 {
			t.Fatalf("device %d could not claim its compatible work: %+v %v", deviceID, claim, err)
		}
		node := BranchActor{MemberID: 7, DeviceID: deviceID, Devices: devices}
		branchDo(t, &p, node, BranchCommand{Type: "ready", RequestID: "hetero-ready-" + strconv.Itoa(i), BranchID: claim.BranchID, Epoch: 1})
		unit := BranchUnitSpec{Key: "unit", Question: "inspect", Role: "worker", Capabilities: []string{"inspect", "inspect_other"}, Contract: json.RawMessage(`{}`)}
		ur, _, err := ApplyBranchCommand(&p, node, BranchCommand{Type: "plan", RequestID: "hetero-plan-" + strconv.Itoa(i), BranchID: claim.BranchID, Epoch: 1, Unit: &unit}, testTime())
		if err != nil {
			t.Fatalf("device %d failed to plan: %v", deviceID, err)
		}
		branch := findBranch(&p, claim.BranchID)
		branch.LeaseUntil = testTime().Add(10)
		allowed := "inspect"
		denied := "inspect_other"
		if deviceID == 12 {
			allowed, denied = denied, allowed
		}
		start := func(tool, id string) error {
			op := BranchOperation{ID: id, Epoch: 1, UnitID: ur.UnitID, Kind: "tool", Role: "worker", Tool: tool, InputHash: ContentHash([]byte(id))}
			_, _, err := ApplyBranchCommand(&p, node, BranchCommand{Type: "start", RequestID: id, BranchID: claim.BranchID, Epoch: 1, Operation: &op}, testTime())
			return err
		}
		if err := start(allowed, "allowed-"+strconv.FormatInt(deviceID, 10)); err != nil {
			t.Fatalf("device %d could not use own capability %s: %v", deviceID, allowed, err)
		}
		// Complete the in-flight operation so the second authorization is tested independently.
		pbr := findBranch(&p, claim.BranchID)
		started := pbr.Operations[len(pbr.Operations)-1]
		branchDo(t, &p, node, BranchCommand{Type: "end", RequestID: "end-" + strconv.FormatInt(deviceID, 10), BranchID: claim.BranchID, Epoch: 1, Operation: &started})
		if err := start(denied, "denied-"+strconv.FormatInt(deviceID, 10)); !errors.Is(err, ErrBranchDenied) {
			t.Fatalf("device %d used peer capability %s: %v", deviceID, denied, err)
		}
	}
}

func TestBranchSetupExtendPolicyPreservesDeviceBindings(t *testing.T) {
	p := branchTestProject()
	p.State = "paused"
	p.Policy.DeviceRoles = map[string]map[string][]string{
		"11": {"planner": {}, "worker": {"inspect"}, "reviewer": {"read_material"}},
	}
	p.Policy.Constraints = []string{"authorized assets only"}
	p.Revision = 1
	update := BranchPolicy{Budget: p.Policy.Budget + 1, DeviceRoles: map[string]map[string][]string{"11": {"worker": {"read_material", "inspect"}}}, Constraints: []string{"replace constraints"}}
	if _, _, err := ApplyBranchCommand(&p, BranchActor{Admin: true}, BranchCommand{Type: "extend_policy", RequestID: "extend-bound", Revision: p.Revision, Policy: &update}, testTime()); err != nil {
		t.Fatalf("extend policy rejected: %v", err)
	}
	if len(p.Policy.DeviceRoles["11"]["planner"]) != 0 || !stringContains(p.Policy.DeviceRoles["11"]["worker"], "inspect") || stringContains(p.Policy.DeviceRoles["11"]["worker"], "read_material") {
		t.Fatalf("extend policy changed device binding: %+v", p.Policy.DeviceRoles)
	}
	if !reflect.DeepEqual(p.Policy.Constraints, []string{"authorized assets only"}) {
		t.Fatalf("extend policy changed constraints: %+v", p.Policy.Constraints)
	}
}

func testTime() time.Time { return time.Unix(100, 0) }
