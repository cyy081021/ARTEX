package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/collab"
	"github.com/Autumn-27/artex/db"
)

type branchSetupOptions struct {
	Budget            int64 `json:"budget"`
	MaxToolSeconds    int   `json:"max_tool_seconds"`
	MinToolIntervalMS int   `json:"min_tool_interval_ms"`
	AutoPublish       *bool `json:"auto_publish"`
	AutoDispatch      *bool `json:"auto_dispatch"`
	AutoReview        *bool `json:"auto_review"`
	IncludeOtherKind  bool  `json:"include_other_kind"`
	IncludeDynamic    bool  `json:"include_dynamic"`
}

type branchSetupRoleView struct {
	Key string `json:"key"`
	collab.BranchSetupRole
}
type branchSetupDeviceView struct {
	ID         int64                 `json:"id"`
	Name       string                `json:"name"`
	MemberID   int64                 `json:"member_id"`
	MemberName string                `json:"member_name"`
	Online     bool                  `json:"online"`
	Matched    bool                  `json:"matched"`
	Roles      []branchSetupRoleView `json:"roles"`
	Issues     []string              `json:"issues"`
}
type branchSetupPlan struct {
	Token        string                  `json:"token"`
	ExpiresAt    time.Time               `json:"expires_at"`
	Task         any                     `json:"task"`
	Assets       []collab.BranchAsset    `json:"assets"`
	Constraints  []db.Constraint         `json:"constraints"`
	Materials    []db.ReverseArtifact    `json:"materials"`
	Devices      []branchSetupDeviceView `json:"devices"`
	Options      branchSetupOptions      `json:"options"`
	Blockers     []string                `json:"blockers"`
	Warnings     []string                `json:"warnings"`
	CanEnable    bool                    `json:"can_enable"`
	policy       collab.BranchPolicy
	sourceDigest string
}

func (s *Server) branchSetup(w http.ResponseWriter, r *http.Request) {
	p, team, t, ok := s.teamTaskScope(w, r, "manage")
	if !ok {
		return
	}
	var options branchSetupOptions
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if decode(r, &options) != nil {
		writeErr(w, 400, "配置选项无效")
		return
	}
	plan, err := s.buildBranchSetup(r, team, t.ID, options)
	if err != nil {
		branchError(w, err)
		return
	}
	plan.ExpiresAt = time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)
	plan.Token = s.branchSetupToken(plan, team, p.MemberID, p.Admin)
	writeJSON(w, 200, plan)
}

func normalizeBranchSetupOptions(v branchSetupOptions) (branchSetupOptions, error) {
	if v.AutoPublish == nil {
		v.AutoPublish = new(bool)
		*v.AutoPublish = true
	}
	if v.AutoDispatch == nil {
		v.AutoDispatch = new(bool)
		*v.AutoDispatch = true
	}
	if v.AutoReview == nil {
		v.AutoReview = new(bool)
		*v.AutoReview = true
	}
	if v.Budget == 0 {
		v.Budget = 100
	}
	if v.MaxToolSeconds == 0 {
		v.MaxToolSeconds = 60
	}
	if v.Budget < 1 || v.Budget > 100000 || v.MaxToolSeconds < 1 || v.MaxToolSeconds > 60 || v.MinToolIntervalMS < 0 || v.MinToolIntervalMS > 60000 {
		return v, fmt.Errorf("预算、时限或调用间隔超出允许范围")
	}
	return v, nil
}

func (s *Server) buildBranchSetup(r *http.Request, team, task int64, options branchSetupOptions) (*branchSetupPlan, error) {
	opts, err := normalizeBranchSetupOptions(options)
	if err != nil {
		return nil, err
	}
	source, err := s.m.pg.BranchSetupSource(r.Context(), team, task)
	if err != nil {
		return nil, err
	}
	v := &branchSetupPlan{Task: source.Task, Assets: []collab.BranchAsset{}, Constraints: source.Constraints, Materials: source.Materials, Devices: []branchSetupDeviceView{}, Options: opts, Blockers: []string{}, Warnings: []string{}, sourceDigest: source.Digest}
	if !source.Shared {
		return nil, db.ErrTeamCollaborationDenied
	}
	if source.Enabled {
		v.Blockers = append(v.Blockers, "此主任务已启用分支协作，请在现有工作台管理")
	}
	if !source.Task.Paused {
		v.Blockers = append(v.Blockers, "请先暂停主任务，等待当前操作完成后重新生成配置")
	}
	if db.IsTerminal(source.Task.Status) || source.Task.Status == "finalizing" {
		v.Blockers = append(v.Blockers, "已结束或正在收尾的任务不能启用协作")
	}
	if strings.TrimSpace(source.Task.Goal) == "" {
		v.Blockers = append(v.Blockers, "主任务尚未设置目标，请先在主任务中补充")
	}
	kind := source.Task.Kind
	if kind == "" {
		kind = "pentest"
	}
	kinds := []string{kind}
	if opts.IncludeOtherKind {
		if kind == "reverse" {
			kinds = append(kinds, "pentest")
		} else {
			kinds = append(kinds, "reverse")
		}
	}
	p := collab.BranchPolicy{Version: 1, Goal: source.Task.Goal, Budget: opts.Budget, MaxToolSeconds: opts.MaxToolSeconds, MinToolIntervalMS: opts.MinToolIntervalMS, AutoPublish: *opts.AutoPublish, AutoDispatch: *opts.AutoDispatch, AutoReview: *opts.AutoReview, Kinds: kinds, PlannerPrompts: map[string]string{}, Roles: map[string]collab.ExecutionConfig{}, DeviceRoles: map[string]map[string][]string{}}
	if p.AutoDispatch && p.Budget < 5 {
		v.Blockers = append(v.Blockers, "自动协作总额度至少为 5 次，用于协调及执行")
	}
	targets := map[string]bool{}
	addAsset := func(id, target string) {
		target = strings.TrimSpace(target)
		if target == "" || targets[target] {
			return
		}
		targets[target] = true
		v.Assets = append(v.Assets, collab.BranchAsset{ID: id, Target: target, Version: collab.ContentHash([]byte(target))})
	}
	for _, scope := range source.Scopes {
		switch scope.Kind {
		case "root_domain", "subdomain":
			addAsset(fmt.Sprintf("scope-%d", scope.ID), scope.Domain)
		case "ip", "cidr":
			target := scope.Net
			if prefix, e := netip.ParsePrefix(target); e == nil && prefix.Bits() == prefix.Addr().BitLen() {
				target = prefix.Addr().String()
			}
			addAsset(fmt.Sprintf("scope-%d", scope.ID), target)
		case "company", "icp": // Resolved to concrete registered assets below.
		default:
			v.Warnings = append(v.Warnings, "主任务中的关键词范围只作为上下文，不能自动转换成可执行目标")
		}
	}
	for _, asset := range source.Assets {
		addAsset(fmt.Sprintf("asset-%d", asset.ID), asset.Target)
	}
	if len(source.Assets) > 256 || len(v.Assets) > 256 {
		v.Blockers = append(v.Blockers, "主任务可执行资产超过 256 个，请先在主任务收窄范围；不会静默截断资产")
	}
	if slices.Contains(kinds, "pentest") && len(v.Assets) == 0 {
		v.Blockers = append(v.Blockers, "主任务没有已登记的可执行资产范围，请先在主任务确认范围；不会从目标描述或其他任务猜测资产")
	}
	if len(source.Materials) > 16 {
		v.Blockers = append(v.Blockers, "主任务材料超过 16 份，请先整理主任务材料")
	}
	var materialSize int64
	for _, m := range source.Materials {
		materialSize += m.SizeBytes
		if m.SizeBytes < 0 || m.SizeBytes > 256<<20 {
			v.Blockers = append(v.Blockers, "主任务存在超过 256 MiB 的材料，请先整理材料")
		}
		p.Materials = append(p.Materials, collab.Material{ID: m.SHA256, SHA256: m.SHA256, Name: m.Name, Size: m.SizeBytes})
	}
	if materialSize > 512<<20 {
		v.Blockers = append(v.Blockers, "主任务材料总量超过 512 MiB，请先整理材料")
	}
	if slices.Contains(kinds, "reverse") && len(source.Materials) == 0 {
		v.Warnings = append(v.Warnings, "当前主任务没有逆向材料；逆向分支执行前仍需通过材料或跨流程协助授权")
	}
	if opts.IncludeDynamic && !slices.Contains(kinds, "reverse") {
		v.Blockers = append(v.Blockers, "动态观察需要先启用逆向工作类型")
	}
	for _, c := range source.Constraints {
		p.Constraints = append(p.Constraints, "["+c.Kind+"] "+c.Text)
	}
	wanted := map[string]bool{}
	for _, k := range kinds {
		roles := []string{"planner", "worker", "reviewer"}
		if k == "reverse" {
			roles = []string{"reverse_planner", "reverse_static", "reverse_reviewer"}
			if opts.IncludeDynamic {
				roles = append(roles, "reverse_dynamic")
			}
		}
		for _, role := range roles {
			wanted[role] = true
		}
	}
	roleNames := []string{}
	for role := range wanted {
		roleNames = append(roleNames, role)
	}
	sort.Strings(roleNames)
	matchedKinds := map[string]bool{}
	for _, d := range source.Devices {
		view := branchSetupDeviceView{ID: d.ID, Name: d.Name, MemberID: d.MemberID, MemberName: d.MemberName, Online: d.Online, Roles: []branchSetupRoleView{}, Issues: []string{}}
		var caps struct {
			Protocol int                      `json:"branch_protocol"`
			Enabled  bool                     `json:"execution_enabled"`
			Report   collab.BranchSetupReport `json:"branch_setup"`
		}
		_ = json.Unmarshal(d.Capabilities, &caps)
		if !d.Active {
			view.Issues = append(view.Issues, "设备或成员已撤销")
		}
		if !d.Online {
			view.Issues = append(view.Issues, "设备离线，请启动成员 Node 后重新生成配置")
		}
		if !d.Permitted {
			view.Issues = append(view.Issues, "成员尚未获得此主任务的查看和执行权限")
		}
		if !caps.Enabled || caps.Protocol != collab.BranchProtocol {
			view.Issues = append(view.Issues, "设备尚未启用分支执行")
		}
		if caps.Report.Version != 1 {
			view.Issues = append(view.Issues, "请更新并重新启动成员 Node，以获取自动配置检查结果")
		}
		approved := map[string][]string{}
		for _, role := range roleNames {
			entry, exists := caps.Report.Roles[role]
			if !exists {
				entry = collab.BranchSetupRole{Capabilities: []string{}, Issues: []string{"role_unconfigured"}}
			}
			entry.Capabilities = append([]string{}, entry.Capabilities...)
			entry.Issues = append([]string{}, entry.Issues...)
			if role == "reviewer" || role == "reverse_reviewer" {
				entry.Capabilities = []string{"read_material"}
			}
			if role == "planner" || role == "reverse_planner" {
				entry.Capabilities = []string{}
			}
			sort.Strings(entry.Capabilities)
			entry.Capabilities = slices.Compact(entry.Capabilities)
			if !entry.Ready {
				entry.Capabilities = []string{}
			}
			if entry.Ready {
				approved[role] = entry.Capabilities
			}
			view.Roles = append(view.Roles, branchSetupRoleView{Key: role, BranchSetupRole: entry})
		}
		for _, k := range kinds {
			needed := []string{"planner", "worker", "reviewer"}
			if k == "reverse" {
				needed = []string{"reverse_planner", "reverse_static", "reverse_reviewer"}
			}
			ready := true
			for _, role := range needed {
				if _, ok := approved[role]; !ok {
					ready = false
				}
			}
			if ready && len(view.Issues) == 0 {
				view.Matched = true
				matchedKinds[k] = true
			}
		}
		if view.Matched {
			p.DeviceRoles[strconv.FormatInt(d.ID, 10)] = approved
		}
		if !view.Matched && len(view.Issues) == 0 {
			view.Issues = append(view.Issues, "同一执行设备需要配置对应流程的规划、执行和核验角色")
		}
		v.Devices = append(v.Devices, view)
	}
	for _, k := range kinds {
		if !matchedKinds[k] {
			v.Blockers = append(v.Blockers, "没有就绪且已获任务授权的设备可承接 "+k+" 流程")
		}
	}
	if len(p.DeviceRoles) > 256 {
		v.Blockers = append(v.Blockers, "匹配设备超过 256 台，请先整理团队设备")
	}
	// Freeze the approved per-device capability sets. The policy-level union is
	// only an authorization ceiling; each device receives its own subset.
	for _, role := range roleNames {
		k := "pentest"
		if strings.HasPrefix(role, "reverse_") {
			k = "reverse"
		}
		prompt := "你是渗透分支的独立技术核验员。只核对授权材料、原始证据和验收标准。区分阴性结果、未验证及反证。不能替代成员独立复核或确认主目标完成。"
		if role != "reviewer" {
			agent, e := s.m.pg.GetAgentByKey(role)
			if e != nil || agent == nil || !agent.Enabled {
				v.Blockers = append(v.Blockers, "主端所需角色未启用："+role)
				continue
			}
			saved, e := s.m.pg.CurrentPrompt(agent.ID)
			if e != nil {
				return nil, e
			}
			prompt = agent.Description + "\n" + saved
		}
		if len(p.Constraints) > 0 {
			prompt += "\n\n主任务明确限制（所有分支必须遵守）：\n" + strings.Join(p.Constraints, "\n")
		}
		if role == "planner" || role == "reverse_planner" {
			p.PlannerPrompts[k] = prompt
			continue
		}
		toolSet := map[string]bool{}
		for _, roles := range p.DeviceRoles {
			for _, cap := range roles[role] {
				toolSet[cap] = true
			}
		}
		tools := []string{}
		for cap := range toolSet {
			tools = append(tools, cap)
		}
		sort.Strings(tools)
		p.Roles[role] = collab.ExecutionConfig{Version: 1, Kind: k, Role: role, SystemPrompt: prompt, MaxTurns: 16, BudgetSeconds: opts.MaxToolSeconds, Capabilities: tools}
	}
	p.Assets = v.Assets
	v.policy = p
	if len(v.Blockers) == 0 {
		if err = collab.ValidateBranchPolicy(p); err != nil {
			v.Blockers = append(v.Blockers, "自动配置超出分支策略限制，请检查主任务范围和设备报告")
		}
	}
	v.CanEnable = len(v.Blockers) == 0
	v.Warnings = append(v.Warnings, "设备匹配只验证已上报的本地配置，不会调用模型或工具。启用后主任务保持暂停，成员按已有任务权限加入分支工作台。")
	return v, nil
}

func (s *Server) branchSetupToken(v *branchSetupPlan, team, member int64, admin bool) string {
	raw, _ := json.Marshal(struct {
		Domain       string
		Team, Member int64
		Admin        bool
		Expires      int64
		Source       string
		Options      branchSetupOptions
		Policy       collab.BranchPolicy
	}{"artex-branch-setup-v1", team, member, admin, v.ExpiresAt.Unix(), v.sourceDigest, v.Options, v.policy})
	mac := hmac.New(sha256.New, s.jwtKey)
	_, _ = mac.Write(raw)
	return strconv.FormatInt(v.ExpiresAt.Unix(), 10) + "." + hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) confirmedBranchSetup(r *http.Request, team, task, member int64, admin bool, token string, options branchSetupOptions) (*branchSetupPlan, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("请先生成并核对自动配置")
	}
	stamp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || stamp <= time.Now().Unix() || stamp > time.Now().Add(11*time.Minute).Unix() {
		return nil, fmt.Errorf("配置预览已过期，请重新生成并核对")
	}
	plan, err := s.buildBranchSetup(r, team, task, options)
	if err != nil {
		return nil, err
	}
	plan.ExpiresAt = time.Unix(stamp, 0).UTC()
	if !hmac.Equal([]byte(token), []byte(s.branchSetupToken(plan, team, member, admin))) {
		return nil, fmt.Errorf("主任务、成员权限、设备或选项已变化，请重新生成并核对配置")
	}
	if !plan.CanEnable {
		return nil, fmt.Errorf("当前配置未就绪：%s", strings.Join(plan.Blockers, "；"))
	}
	return plan, nil
}
