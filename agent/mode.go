package agent

import "context"

// Task modes. "normal" is the product default and must keep behaving exactly as
// before; "ctf" is an incremental overlay on top of it (time box, route switching,
// flag-first acceptance) so every future improvement to normal mode is inherited.
const (
	ModeNormal = "normal"
	ModeCTF    = "ctf"
)

type modeKey struct{}

// WithMode is set from the persisted task mode, never inferred from the task text.
// A zero context means normal mode.
func WithMode(ctx context.Context, mode string) context.Context {
	if mode != ModeCTF {
		mode = ModeNormal
	}
	return context.WithValue(ctx, modeKey{}, mode)
}

func ModeOf(ctx context.Context) string {
	if mode, _ := ctx.Value(modeKey{}).(string); mode == ModeCTF {
		return ModeCTF
	}
	return ModeNormal
}

func IsCTF(ctx context.Context) bool { return ModeOf(ctx) == ModeCTF }

// ctfOverlay returns the role-specific text appended in CTF mode. It is additive
// on purpose: the normal policy (hard floor, depth-first, evidence discipline)
// stays in force, and only these CTF-specific rules are layered on top.
func ctfOverlay(role string) string {
	switch role {
	case "goals", "reverse_goals":
		return "\n\n【CTF 模式】唯一交付是 flag（形如 flag{...}，以任务给出的格式为准）。把每个 flag 拆成一条可核验目标；攻击面、漏洞、信息收集只作为逼近 flag 的路径，不要把它们本身写成交付目标。目标只有在拿到 flag 原文及其来源证据后才能 prove_goal；没拿到 flag 之前，任何\"看起来能打通\"的判断都只能记录为 inferred 事实。"
	case "planner", "reverse_planner":
		return "\n\n【CTF 模式】时间盒优先：先按剩余时间决定这一轮是扩面还是深打，时间过半仍未找到入口时优先换路线而不是加深现有路线。同一路线连续两次无进展（无新事实、无新入口、无 flag 进展）禁止再派同义意图，必须换路线或用 record_planning_decision 登记卡点及解锁条件。多条互不依赖的路线（如 web 入口链、二进制输入面）可并行派意图，但串行依赖仍按 TodoWrite 分步。拿到 flag 后立即收敛，不扩大战果。"
	case "worker", "reverse_static", "reverse_dynamic":
		return "\n\n【CTF 模式】拿到 flag 时立刻调用 submit_flag(flag, source, note) 记账：它会把 flag 写入本任务台账、生成一条 observed 事实，重复提交只返回 duplicate。随后用 record_fact 写一条 observed 事实引用来源（请求/命令/响应片段），让 planner 能对该目标 prove_goal。拿不到 flag 时用 list_flags 确认这条路线是否已经拿到过，避免重复劳动。flag 之外的安全问题只在顺手时记一条 inferred 事实，不升级为候选结论、不扩大测试范围。"
	case "reviewer", "reverse_reviewer":
		return "\n\n【CTF 模式】只对 flag 与最终 exploit 强制独立复核；中间观察、静态候选不必逐条派复核，避免占用比赛时间。复核 flag 时必须核对原文与来源证据一致，并确认 list_flags 里那条记录与结论引用的来源相同。"
	default:
		return ""
	}
}
