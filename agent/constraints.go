package agent

import (
	"strings"

	"github.com/Autumn-27/artex/db"
)

// constraintBlock renders this task's operation constraints (task_constraints) as a
// high-priority block appended to the planner/worker system prompt. allow/deny are
// grouped; empty string when there are no constraints (or ts is nil). The framing
// deliberately puts these ABOVE the exploration/expansion heuristics so a declared
// boundary wins the tug-of-war against "chase another entry surface".
func constraintBlock(ts *db.ExplorationStore) string {
	if ts == nil {
		return ""
	}
	rows, err := ts.ListConstraints()
	if err != nil || len(rows) == 0 {
		return ""
	}
	return renderConstraints(rows)
}

// renderConstraints renders one already-loaded constraint snapshot. Callers that
// need to keep prompts and execution-boundary checks on the same snapshot can
// load once and pass the rows to both paths.
func renderConstraints(rows []db.Constraint) string {
	var allow, deny, rules []string
	for _, c := range rows {
		text := strings.TrimSpace(c.Text)
		if text == "" {
			continue
		}
		if c.Kind == "allow" {
			allow = append(allow, "- "+text)
		} else if c.Kind == "deny" {
			deny = append(deny, "- "+text)
		} else if c.Kind == "rule" {
			rules = append(rules, "- "+text)
		}
	}
	if len(allow) == 0 && len(deny) == 0 && len(rules) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【操作约束（最高优先级，凌驾于下方一切探索/拓面启发式；每生成一条意图、每执行一个动作前都必须先自检是否违反，违反即不得进行）】：")
	if len(allow) > 0 {
		b.WriteString("\n允许的操作：\n")
		b.WriteString(strings.Join(allow, "\n"))
	}
	if len(deny) > 0 {
		b.WriteString("\n禁止的操作：\n")
		b.WriteString(strings.Join(deny, "\n"))
	}
	if len(rules) > 0 {
		b.WriteString("\n规则：\n")
		b.WriteString(strings.Join(rules, "\n"))
	}
	b.WriteString("\n这些约束与主任务已确认的资产范围共同生效。allow 中明确限定的范围与 deny 中的禁止事项必须遵守；rule 是操作要求，不是额外的资产白名单。此处未列出允许项，不表示已确认的任务范围被清空。已授权范围内且符合约束的工作直接推进，无需重复请求相同许可；发现的新目标仍须核对主任务范围，确实超出范围的只记录线索，不据此扩大执行范围。")
	return b.String()
}
