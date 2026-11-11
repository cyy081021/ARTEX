package collab

import (
	"fmt"
	"sort"
	"time"
)

// DispatchBranches operates only on a server-built set of online, permitted
// devices. It uses the same command validation and budget accounting as manual
// work. No network calls, model requests or task completion happen here.
func DispatchBranches(p *BranchProject, devices map[int64]BranchDevice, now time.Time) ([]BranchEvent, error) {
	if !p.Policy.AutoDispatch || p.State != "running" || len(p.Policy.DeviceRoles) == 0 {
		return nil, nil
	}
	var events []BranchEvent
	apply := func(a BranchActor, c BranchCommand) error {
		_, es, err := ApplyBranchCommand(p, a, c, now)
		events = append(events, es...)
		return err
	}
	seeded := false
	for _, w := range p.Pool {
		if w.Spec.Coordinator {
			seeded = true
			break
		}
	}
	if !seeded {
		budget := p.Policy.Budget / 5
		if budget > 20 {
			budget = 20
		}
		if budget < 1 {
			budget = 1
		}
		if p.Policy.Budget-totalBudget(p) > budget {
			kind := p.Policy.Kinds[0]
			roles := []string{"worker", "reviewer"}
			if kind == "reverse" {
				roles = []string{"reverse_static", "reverse_reviewer"}
			}
			w := BranchWorkSpec{Title: "协作调度", Question: "根据主任务目标和已有进展拆分有限工作，匹配各设备可用能力，为子工作分配授权资产、材料、依赖及预算；汇总核验结果，按项目设置自动接收或转人工复审。", Kind: kind, Roles: roles, Budget: budget, Coordinator: true, Acceptance: []string{"工作范围与主任务一致，派发具有依据，不代签复核或宣布主任务完成"}}
			for _, a := range p.Policy.Assets {
				w.AssetIDs = append(w.AssetIDs, a.ID)
			}
			for _, m := range p.Policy.Materials {
				w.MaterialHashes = append(w.MaterialHashes, m.SHA256)
			}
			if err := apply(BranchActor{Admin: true, Devices: devices}, BranchCommand{Type: "publish", RequestID: "auto-coordinator-v1", Work: &w}); err != nil {
				return nil, err
			}
		}
	}
	ids := []int64{}
	for id := range devices {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	load := map[int64]int{}
	for _, b := range p.Branches {
		if !b.Spec.Coordinator && !stringContains([]string{"accepted", "cancelled", "failed", "review_pending"}, b.State) {
			load[b.DeviceID]++
		}
	}
	for i := range p.Pool {
		w := p.Pool[i]
		if w.State != "published" || w.BranchID != 0 {
			continue
		}
		var best int64
		for _, id := range ids {
			d := devices[id]
			if !d.Active || !d.Online || (!w.Spec.Coordinator && load[id] > 0) {
				continue
			}
			if w.Spec.Restricted && !hasID(w.Spec.Members, d.OwnerID) {
				continue
			}
			a := BranchActor{MemberID: d.OwnerID, Devices: devices}
			if CheckBranchAccess(p, a, 0, "execute") != nil || CheckBranchAccess(p, a, 0, "read") != nil {
				continue
			}
			if _, ok := selectBranchDevice(p.Policy, a, w.Spec, d.OwnerID, id); !ok {
				continue
			}
			if best == 0 || load[id] < load[best] {
				best = id
			}
		}
		if best == 0 {
			continue
		}
		d := devices[best]
		if err := apply(BranchActor{MemberID: d.OwnerID, Devices: devices}, BranchCommand{Type: "claim", RequestID: fmt.Sprintf("auto-claim-%d", w.ID), WorkID: w.ID, DeviceID: best}); err != nil {
			return nil, err
		}
		if !w.Spec.Coordinator {
			load[best]++
		}
	}
	return events, nil
}

func withAutomaticReviewer(policy BranchPolicy, work *BranchWorkSpec) *BranchWorkSpec {
	if !policy.AutoDispatch || work == nil || work.Coordinator {
		return work
	}
	copy := *work
	reviewer := "reviewer"
	if work.Kind == "reverse" {
		reviewer = "reverse_reviewer"
	}
	if _, ok := policy.Roles[reviewer]; ok && !stringContains(work.Roles, reviewer) {
		copy.Roles = append(append([]string{}, work.Roles...), reviewer)
	}
	return &copy
}
