package main

import (
	"sort"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// Apply the node protocol after configured domain guidance, including policies
// saved before branch-specific prompts existed. This does not change grants.
func branchToolProtocol(tools []actool.CoreTool, planner, reviewer, autoReview bool) string {
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name())
	}
	sort.Strings(names)
	s := "\n\n【当前节点执行协议】本会话实际可调用工具：" + strings.Join(names, ", ") + "。配置提示词中的领域方法和项目约束继续有效；涉及本机任务图、工具名称、提交方式或复核模式的旧说明，以本节和当前工具 schema 为准。不要调用清单外的工具，也不因缺少旧接口而要求人工操作。已确认范围内、具备执行条件的工作直接推进，真正缺少必要能力时才报告具体缺口。"
	if planner {
		s += "\n本轮输入已包含分支目标、工作单、结果、依赖与预算，先使用这些内容。用 propose_work 安排工作，用 branch_wait 等待具体条件，用 submit_branch 提交分支结果；使用已提供的协调工具处理跨分支协助。任务图写入和主任务完成判定由主端负责，本分支不调用本机的 add_intent、prove_goal 或 record_planning_decision。已有充分结果直接复用，待核验工作按实际证据缺口安排。"
	} else {
		s += "\n工具原始结果由节点自动留存；最后按输入 final_format 返回一个 JSON 对象，节点负责结果与证据回传。不要额外调用本机的 record_fact、report_finding、complete_intent、reverse_submit_conclusion 或 reverse_review_conclusion 来落库，也不要因这些接口不存在而等待。candidate 表示已产出待验收结果，不要求执行者自行签署主任务达成。"
	}
	if reviewer {
		if autoReview {
			s += "\n当前启用自动核验：证据充分且满足验收条件时返回 accept，不再另等成员逐项确认；只有影响结论的不明确、缺失或冲突转 needs_human。此模式取代旧提示中的强制成员复核要求。"
		} else {
			s += "\n当前使用人工复核：返回技术核验结果供成员复审，不自行接收分支或声明主任务完成。"
		}
		s += "已有证据足够时直接核验，不要求每个历史工具调用都成功，也不为无关细节重新执行整条流程。"
	}
	return s
}
