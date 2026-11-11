package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
)

type teamContentField struct {
	Label string `json:"label"`
	Value string `json:"value"`
}
type teamContentColumn struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}
type teamContentRow struct {
	ID     string            `json:"id"`
	Cells  map[string]string `json:"cells"`
	Detail string            `json:"detail,omitempty"`
}
type teamContentArticle struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Meta   string `json:"meta,omitempty"`
	Text   string `json:"text"`
	Format string `json:"format,omitempty"`
}
type teamContentNode struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Kind   string `json:"kind"`
	Status string `json:"status,omitempty"`
	Detail string `json:"detail,omitempty"`
}
type teamContentEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label,omitempty"`
}
type teamContentGraph struct {
	Nodes []teamContentNode `json:"nodes"`
	Edges []teamContentEdge `json:"edges"`
}
type teamTaskContent struct {
	Section  string               `json:"section"`
	Title    string               `json:"title"`
	Summary  []teamContentField   `json:"summary,omitempty"`
	Columns  []teamContentColumn  `json:"columns,omitempty"`
	Rows     []teamContentRow     `json:"rows"`
	Articles []teamContentArticle `json:"articles"`
	Graph    *teamContentGraph    `json:"graph,omitempty"`
	Page     int                  `json:"page"`
	PageSize int                  `json:"page_size"`
	Total    int                  `json:"total"`
	HasMore  bool                 `json:"has_more"`
}

var teamContentTitles = map[string]string{"overview": "总览", "graph": "探索链路", "broadcast": "播报板", "findings": "发现", "finding-relations": "漏洞关联", "retests": "复测", "assets": "测试资产", "coverage": "资产覆盖图", "intercept": "拦截审批", "report": "报告", "workflow-requests": "跨流程协助", "reverse": "分析档案"}

// All sections share the existing task read permission. No management routes or
// mutation handlers are reachable through this reader, including detail links.
func (s *Server) teamTaskContent(w http.ResponseWriter, r *http.Request) {
	_, _, task, ok := s.teamTaskScope(w, r, "read")
	if !ok {
		return
	}
	section := r.PathValue("section")
	title, ok := teamContentTitles[section]
	if !ok {
		writeErr(w, 404, "没有此任务栏目")
		return
	}
	page, size := atoiDefault(r.URL.Query().Get("page"), 1), atoiDefault(r.URL.Query().Get("size"), 50)
	if page < 1 || page > 1000000 || size < 1 || size > 100 {
		writeErr(w, 400, "分页参数无效")
		return
	}
	v := &teamTaskContent{Section: section, Title: title, Rows: []teamContentRow{}, Articles: []teamContentArticle{}, Page: page, PageSize: size}
	var err error
	if detail := r.PathValue("item"); detail != "" {
		if section != "findings" && section != "assets" {
			writeErr(w, 404, "没有此详情")
			return
		}
		id, e := strconv.ParseInt(detail, 10, 64)
		if e != nil || id < 1 {
			writeErr(w, 400, "记录编号无效")
			return
		}
		if section == "assets" {
			err = s.teamAssetContent(r, task, id, v)
		} else {
			err = s.teamFindingContent(r, task, id, v)
		}
	} else {
		err = s.readTeamTaskContent(r, task, v)
	}
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "此记录不属于当前共享任务")
		return
	}
	if err != nil {
		writeErr(w, 500, "读取任务资料失败，请稍后重试")
		return
	}
	v.HasMore = v.Page*v.PageSize < v.Total
	writeJSON(w, 200, v)
}

func contentColumns(names ...string) []teamContentColumn {
	out := []teamContentColumn{}
	for i := 0; i+1 < len(names); i += 2 {
		out = append(out, teamContentColumn{names[i], names[i+1]})
	}
	return out
}
func contentRow(id int64, values ...string) teamContentRow {
	r := teamContentRow{ID: strconv.FormatInt(id, 10), Cells: map[string]string{}}
	for i := 0; i+1 < len(values); i += 2 {
		r.Cells[values[i]] = values[i+1]
	}
	return r
}
func contentTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
func contentFirst(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
func contentLabel(value string) string {
	switch value {
	case "completed":
		return "已完成"
	case "reproduced":
		return "已复现"
	case "inconclusive":
		return "尚无定论"
	case "created":
		return "已创建"
	case "unknown":
		return "未标注"
	}
	labels := map[string]string{"goal": "目标", "intent": "工作", "fact": "事实", "finding": "发现", "hint": "线索", "digest": "摘要", "critical": "严重", "high": "高", "medium": "中", "low": "低", "open": "待处理", "pending": "待处理", "running": "运行中", "paused": "已暂停", "done": "已完成", "confirmed": "已确认", "accepted": "已接收", "proposed": "待核验", "rejected": "已驳回", "unresolved": "未解决", "met": "已达成", "unmet": "未达成", "blocked": "受阻", "failed": "失败", "cancelled": "已取消", "fixed": "已修复", "false_positive": "误报", "in_progress": "处理中", "allow": "允许", "deny": "禁止", "rule": "规则", "approved": "已批准", "denied": "已拒绝", "resolved": "已处理", "root_domain": "根域名", "subdomain": "子域名", "ip": "IP", "service": "服务", "endpoint": "端点", "app": "应用", "company": "单位", "model": "模型", "human": "人工", "manual": "人工", "prerequisite": "前置条件", "enables": "提供能力", "supports": "证据支持", "contradicts": "相互矛盾", "verified": "已核验"}
	if v, ok := labels[value]; ok {
		return v
	}
	return value
}
func contentPayload(raw json.RawMessage) (string, string) {
	var p map[string]any
	if json.Unmarshal(raw, &p) != nil {
		return "", ""
	}
	get := func(key string) string { v, _ := p[key].(string); return v }
	title := contentFirst(get("name"), get("title"), get("question"), get("text"), get("summary"), get("description"))
	lines := []string{}
	seen := map[string]bool{}
	for _, key := range []string{"text", "question", "answer", "description", "summary", "content", "result", "claim", "reason", "rationale", "review", "limitations", "error"} {
		if text := get(key); text != "" && !seen[text] {
			lines = append(lines, text)
			seen[text] = true
		}
	}
	for _, key := range []string{"acceptance", "evidence"} {
		if value, ok := p[key]; ok {
			if text := contentReadable(value); text != "" {
				lines = append(lines, text)
			}
		}
	}
	return title, strings.Join(lines, "\n\n")
}

// Human-readable evidence fields, without an execution trace or raw tool input.
func contentReadable(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		out := []string{}
		for _, item := range x {
			if text := contentReadable(item); text != "" {
				out = append(out, "- "+text)
			}
		}
		return strings.Join(out, "\n")
	case map[string]any:
		out := []string{}
		keys := []string{"summary", "answer", "observation", "evidence", "poc", "locator", "conclusion", "status", "reason", "limitations"}
		for _, key := range keys {
			if value, ok := x[key]; ok {
				if text := contentReadable(value); text != "" {
					out = append(out, key+"："+text)
				}
			}
		}
		return strings.Join(out, "\n")
	}
	return ""
}
func paginateContent(v *teamTaskContent, q string) {
	if q = strings.ToLower(strings.TrimSpace(q)); q != "" {
		rows := []teamContentRow{}
		for _, r := range v.Rows {
			for _, value := range r.Cells {
				if strings.Contains(strings.ToLower(value), q) {
					rows = append(rows, r)
					break
				}
			}
		}
		v.Rows = rows
		articles := []teamContentArticle{}
		for _, a := range v.Articles {
			if strings.Contains(strings.ToLower(a.Title+" "+a.Text+" "+a.Meta), q) {
				articles = append(articles, a)
			}
		}
		v.Articles = articles
	}
	v.Total = len(v.Rows) + len(v.Articles)
	start := (v.Page - 1) * v.PageSize
	end := start + v.PageSize
	rows, articles := v.Rows, v.Articles
	v.Rows = []teamContentRow{}
	v.Articles = []teamContentArticle{}
	for i, row := range rows {
		if i >= start && i < end {
			v.Rows = append(v.Rows, row)
		}
	}
	for i, a := range articles {
		index := len(rows) + i
		if index >= start && index < end {
			v.Articles = append(v.Articles, a)
		}
	}
}

func (s *Server) readTeamTaskContent(r *http.Request, t *db.Task, v *teamTaskContent) error {
	pg := s.m.pg
	store := pg.Exploration(t.ExplorationID)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	switch v.Section {
	case "overview":
		v.Summary = []teamContentField{{"状态", contentLabel(t.Status)}, {"类型", map[bool]string{true: "逆向", false: "渗透"}[t.Kind == "reverse"]}, {"创建时间", contentTime(t.CreatedAt)}}
		v.Articles = append(v.Articles, teamContentArticle{ID: "goal", Title: "任务目标", Text: t.Goal}, teamContentArticle{ID: "description", Title: "任务说明", Text: t.Description})
		goals, err := store.ListByKind(db.KindGoal, 10000)
		if err != nil {
			return err
		}
		for _, g := range goals {
			title, text := contentPayload(g.Payload)
			v.Articles = append(v.Articles, teamContentArticle{ID: fmt.Sprint(g.ID), Title: contentFirst(title, "目标"), Text: text, Meta: contentLabel(g.State)})
		}
		constraints, err := store.ListConstraints()
		if err != nil {
			return err
		}
		for _, c := range constraints {
			v.Articles = append(v.Articles, teamContentArticle{ID: fmt.Sprint("constraint-", c.ID), Title: contentLabel(c.Kind), Text: c.Text})
		}
		scopes, err := s.m.Assets().ListTaskScopeWithSources(t.ID)
		if err != nil {
			return err
		}
		for _, scope := range scopes {
			v.Articles = append(v.Articles, teamContentArticle{ID: fmt.Sprint("scope-", scope.ID), Title: "测试范围 · " + contentLabel(scope.Kind), Text: contentFirst(scope.CompanyName, scope.Domain, scope.Net, scope.Value), Meta: scope.Reason})
		}
		if t.CoverageEnabled {
			cov, e := s.m.Assets().TaskCoverageWithSources(t.ID)
			if e != nil {
				return e
			}
			v.Summary = append(v.Summary, teamContentField{"范围内资产", fmt.Sprint(cov.Denominator)}, teamContentField{"已测试资产（参考）", fmt.Sprint(cov.Tested)})
		}
	case "graph":
		v.Graph = &teamContentGraph{Nodes: []teamContentNode{}, Edges: []teamContentEdge{}}
		sources, err := store.DirectSourceStores()
		if err != nil {
			return err
		}
		stores := []db.DirectSourceStore{{Task: db.TaskSource{TaskID: t.ID}, Store: store}}
		stores = append(stores, sources...)
		for _, source := range stores {
			nodes, e := source.Store.Nodes(2000)
			if e != nil {
				return e
			}
			edges, e := source.Store.Edges(5000)
			if e != nil {
				return e
			}
			known := map[int64]bool{}
			for _, n := range nodes {
				title, text := contentPayload(n.Payload)
				meta := contentLabel(n.State)
				if source.Task.TaskID != t.ID {
					meta += " · 来源任务 #" + fmt.Sprint(source.Task.TaskID)
				}
				v.Graph.Nodes = append(v.Graph.Nodes, teamContentNode{ID: fmt.Sprint(n.ID), Label: contentFirst(title, meta), Kind: contentLabel(n.Kind), Status: meta, Detail: text})
				known[n.ID] = true
			}
			for _, edge := range edges {
				if known[edge.From] && known[edge.To] {
					v.Graph.Edges = append(v.Graph.Edges, teamContentEdge{fmt.Sprint(edge.From), fmt.Sprint(edge.To), edge.Rel})
				}
			}
		}
		v.Summary = []teamContentField{{"节点", fmt.Sprint(len(v.Graph.Nodes))}, {"关系", fmt.Sprint(len(v.Graph.Edges))}, {"显示范围", "与主任务一致，每个来源最多 2000 个节点"}}
	case "broadcast":
		nodes, total, err := store.NodesPage(db.NodeFilter{Query: q}, v.Page, v.PageSize)
		if err != nil {
			return err
		}
		v.Total = total
		for _, n := range nodes {
			title, text := contentPayload(n.Payload)
			v.Articles = append(v.Articles, teamContentArticle{ID: fmt.Sprint(n.ID), Title: contentFirst(title, contentLabel(n.Kind)), Text: text, Meta: contentLabel(n.Kind) + " · " + contentLabel(n.State) + " · " + contentTime(n.CreatedAt)})
		}
		return nil
	case "findings":
		items, total, err := pg.TeamTaskFindings(r.Context(), t.ID, q, v.Page, v.PageSize)
		if err != nil {
			return err
		}
		v.Total = total
		v.Columns = contentColumns("name", "名称", "severity", "等级", "status", "状态", "summary", "摘要", "source", "来源")
		for _, f := range items {
			row := contentRow(f.ID, "name", contentFirst(f.Name, f.VulnClass), "severity", contentLabel(f.Severity), "status", contentLabel(f.Status), "summary", f.Summary, "source", "当前任务")
			row.Detail = fmt.Sprint("findings/", f.ID)
			if f.TaskID != nil && *f.TaskID != t.ID {
				row.Cells["source"] = fmt.Sprint("来源任务 #", *f.TaskID)
			}
			v.Rows = append(v.Rows, row)
		}
		return nil
	case "finding-relations":
		nodes, edges, err := pg.FindingGraph(t.ID)
		if err != nil {
			return err
		}
		v.Graph = &teamContentGraph{Nodes: []teamContentNode{}, Edges: []teamContentEdge{}}
		names := map[int64]string{}
		for _, n := range nodes {
			names[n.ID] = n.Name
			v.Graph.Nodes = append(v.Graph.Nodes, teamContentNode{ID: fmt.Sprint(n.ID), Label: n.Name, Kind: contentLabel(n.Severity), Status: contentLabel(n.Status)})
		}
		v.Columns = contentColumns("source", "来源发现", "relation", "关系", "target", "目标发现", "status", "状态", "reason", "依据")
		for _, edge := range edges {
			v.Graph.Edges = append(v.Graph.Edges, teamContentEdge{fmt.Sprint(edge.Source), fmt.Sprint(edge.Target), contentLabel(edge.Kind)})
			v.Rows = append(v.Rows, contentRow(edge.ID, "source", names[edge.Source], "target", names[edge.Target], "relation", contentLabel(edge.Kind), "status", contentLabel(edge.Status), "reason", edge.Rationale+"\n"+edge.Evidence))
		}
	case "retests":
		items, total, err := pg.TeamTaskRetests(r.Context(), t.ID, q, v.Page, v.PageSize)
		if err != nil {
			return err
		}
		v.Total = total
		for _, item := range items {
			v.Articles = append(v.Articles, teamContentArticle{ID: fmt.Sprint(item.ID), Title: fmt.Sprintf("发现 #%d · 复测 #%d", item.FindingID, item.ID), Meta: contentLabel(item.Status) + " · " + contentLabel(item.Verdict) + " · " + contentTime(item.CreatedAt), Text: strings.Join([]string{item.Summary, item.Notes, item.Evidence, item.Error}, "\n\n")})
		}
		return nil
	case "assets":
		items, total, err := pg.TeamTaskAssets(r.Context(), t.ID, q, v.Page, v.PageSize)
		if err != nil {
			return err
		}
		v.Total = total
		v.Columns = contentColumns("target", "资产", "kind", "类型", "ip", "IP", "port", "端口", "service", "服务 / 技术", "title", "标题 / 说明")
		for _, a := range items {
			port := ""
			if a.Port != nil {
				port = fmt.Sprint(*a.Port)
			}
			row := contentRow(a.ID, "target", contentFirst(a.URL, a.Domain, a.IP, a.AppName, a.RootDomain), "kind", contentLabel(a.Type), "ip", a.IP, "port", port, "service", strings.Join(append([]string{a.ServiceType, a.ServiceName}, a.Technologies...), " "), "title", contentFirst(a.PageTitle, a.AppDescription))
			row.Detail = fmt.Sprint("assets/", a.ID)
			v.Rows = append(v.Rows, row)
		}
		return nil
	case "coverage":
		if !t.CoverageEnabled {
			v.Articles = append(v.Articles, teamContentArticle{ID: "disabled", Title: "资产覆盖度未启用", Text: "主任务未启用资产覆盖度。测试资产仍可在对应栏目查看。"})
			break
		}
		graph, err := s.m.Assets().BuildCoverageGraph(t.ID, t.ExplorationID)
		if err != nil {
			return err
		}
		v.Graph = &teamContentGraph{Nodes: []teamContentNode{}, Edges: []teamContentEdge{}}
		for _, n := range graph.Nodes {
			status := "未测试"
			if n.Tested {
				status = "已测试"
			}
			if !n.InScope {
				status = "关联节点"
			}
			v.Graph.Nodes = append(v.Graph.Nodes, teamContentNode{ID: n.Key, Label: n.Label, Kind: contentLabel(n.Kind), Status: status, Detail: strings.Join([]string{n.PageTitle, n.ServiceType, n.URL, n.IP}, "\n")})
		}
		for _, e := range graph.Edges {
			v.Graph.Edges = append(v.Graph.Edges, teamContentEdge{e.Src, e.Dst, "归属"})
		}
		cov, err := s.m.Assets().TaskCoverageWithSources(t.ID)
		if err != nil {
			return err
		}
		v.Summary = []teamContentField{{"范围内资产", fmt.Sprint(cov.Denominator)}, {"已测试（参考）", fmt.Sprint(cov.Tested)}}
	case "intercept":
		items, total, err := pg.ListTaskInterceptsPage(fmt.Sprint(t.ID), v.Page, v.PageSize, db.InterceptApprovalFilter{})
		if q != "" {
			items, err = pg.ListTaskIntercepts(fmt.Sprint(t.ID))
		}
		if err != nil {
			return err
		}
		v.Total = total
		v.Columns = contentColumns("agent", "执行者", "tool", "工具", "status", "状态", "source", "决定来源", "reason", "理由", "time", "时间")
		for _, a := range items {
			v.Rows = append(v.Rows, contentRow(a.ID, "agent", a.AgentName, "tool", a.ToolName, "status", contentLabel(a.Status), "source", contentLabel(a.DecisionSource), "reason", a.Reason, "time", contentTime(a.CreatedAt)))
		}
		if q != "" {
			paginateContent(v, q)
		}
		return nil
	case "report":
		if t.Kind == "reverse" {
			return s.teamReverseContent(t, v, true, q)
		}
		live, ok := s.m.Task(fmt.Sprint(t.ID))
		if !ok {
			return sql.ErrNoRows
		}
		md, err := s.taskReportMarkdown(live)
		if err != nil {
			return err
		}
		v.Articles = append(v.Articles, teamContentArticle{ID: "report", Title: "渗透测试报告", Text: md, Format: "markdown"})
	case "workflow-requests":
		items, err := pg.ListWorkflowRequests(r.Context(), t.ID)
		if err != nil {
			return err
		}
		for _, item := range items {
			var result any
			_ = json.Unmarshal(item.Result, &result)
			text := item.Question + "\n\n验收要求：\n- " + strings.Join(item.Acceptance, "\n- ")
			if resultText := contentReadable(result); resultText != "" {
				text += "\n\n协助结果：\n" + resultText
			}
			v.Articles = append(v.Articles, teamContentArticle{ID: fmt.Sprint(item.ID), Title: fmt.Sprintf("协助请求 #%d", item.ID), Meta: fmt.Sprintf("%s · 任务 #%d → #%d · %s", contentLabel(item.Status), item.SourceTaskID, item.TargetTaskID, contentTime(item.CreatedAt)), Text: text})
		}
	case "reverse":
		return s.teamReverseContent(t, v, false, q)
	}
	paginateContent(v, q)
	return nil
}

func (s *Server) teamFindingContent(r *http.Request, t *db.Task, id int64, v *teamTaskContent) error {
	f, err := s.m.pg.TeamTaskFinding(r.Context(), t.ID, id)
	if err != nil {
		return err
	}
	v.Title = contentFirst(f.Name, f.VulnClass)
	v.Summary = []teamContentField{{"等级", contentLabel(f.Severity)}, {"状态", contentLabel(f.Status)}, {"类型", f.VulnClass}, {"创建时间", contentTime(f.CreatedAt)}}
	v.Articles = append(v.Articles, teamContentArticle{ID: "summary", Title: "发现摘要", Text: f.Summary}, teamContentArticle{ID: "evidence", Title: "证据", Text: f.Evidence}, teamContentArticle{ID: "report", Title: "详细报告", Text: f.Report, Format: "markdown"})
	retests, err := s.m.pg.ListFindingRetests(id)
	if err != nil {
		return err
	}
	for _, item := range retests {
		v.Articles = append(v.Articles, teamContentArticle{ID: fmt.Sprint("retest-", item.ID), Title: "复测记录", Meta: contentLabel(item.Status) + " · " + contentLabel(item.Verdict), Text: item.Summary + "\n\n" + item.Evidence})
	}
	v.Total = len(v.Articles)
	v.Page = 1
	v.PageSize = max(1, v.Total)
	return nil
}

func (s *Server) teamReverseContent(t *db.Task, v *teamTaskContent, asReport bool, q string) error {
	if t.Kind != "reverse" {
		return sql.ErrNoRows
	}
	artifacts, err := s.m.pg.ListReverseArtifacts(t.ID)
	if err != nil {
		return err
	}
	conclusions, err := s.m.pg.ListReverseConclusions(t.ID)
	if err != nil {
		return err
	}
	clean := func(text string) string { return reversePortableText(text, s.m.dir, fmt.Sprint(t.ID), artifacts) }
	v.Summary = []teamContentField{{"材料", fmt.Sprint(len(artifacts))}, {"分析结论", fmt.Sprint(len(conclusions))}}
	for _, a := range artifacts {
		v.Articles = append(v.Articles, teamContentArticle{ID: fmt.Sprint("artifact-", a.ID), Title: a.Name, Meta: fmt.Sprintf("%s · %s · %d 字节", a.Format, a.Version, a.SizeBytes), Text: "SHA256: " + a.SHA256})
	}
	for _, c := range conclusions {
		text := clean(c.Answer) + "\n\n局限：" + clean(c.Limitations) + "\n\n核验说明：" + clean(c.Review)
		for _, e := range c.Evidence {
			text += "\n\n定位：" + clean(e.Locator) + "\n观察：" + clean(e.Observation)
		}
		v.Articles = append(v.Articles, teamContentArticle{ID: fmt.Sprint("conclusion-", c.ID), Title: clean(c.Question), Text: text, Meta: contentLabel(c.State)})
	}
	if asReport {
		var b strings.Builder
		fmt.Fprintf(&b, "# 逆向分析报告\n\n任务：%s\n\n目标：%s\n\n", t.Name, t.Goal)
		for _, a := range v.Articles {
			fmt.Fprintf(&b, "## %s\n\n%s\n\n%s\n\n", a.Title, a.Meta, a.Text)
		}
		v.Articles = []teamContentArticle{{ID: "report", Title: "逆向分析报告", Text: b.String(), Format: "markdown"}}
	}
	paginateContent(v, q)
	return nil
}

func (s *Server) teamAssetContent(r *http.Request, t *db.Task, id int64, v *teamTaskContent) error {
	a, err := s.m.pg.TeamTaskAsset(r.Context(), t.ID, id)
	if err != nil {
		return err
	}
	v.Title = contentFirst(a.URL, a.Domain, a.IP, a.AppName, a.RootDomain)
	v.Summary = []teamContentField{{"类型", contentLabel(a.Type)}, {"最近发现", a.LastSeen}}
	fields := []teamContentField{{"域名", a.Domain}, {"根域名", a.RootDomain}, {"IP", a.IP}, {"地址", a.URL}, {"标题", a.PageTitle}, {"应用", a.AppName}, {"说明", a.AppDescription}, {"应用包名", a.BundleID}, {"备案", contentFirst(a.ICP, a.AppICP)}, {"服务", a.ServiceType + " " + a.ServiceName}, {"技术", strings.Join(a.Technologies, "、")}, {"请求方法", a.Method}, {"DNS 记录", a.RecordType + " " + strings.Join(a.RecordValue, "、")}, {"绑定域名", strings.Join(a.BoundDomains, "、")}}
	if a.Port != nil {
		fields = append(fields, teamContentField{"端口", fmt.Sprint(*a.Port)})
	}
	if a.StatusCode != nil {
		fields = append(fields, teamContentField{"状态码", fmt.Sprint(*a.StatusCode)})
	}
	for i, f := range fields {
		if strings.TrimSpace(f.Value) != "" {
			v.Articles = append(v.Articles, teamContentArticle{ID: fmt.Sprint(i), Title: f.Label, Text: f.Value})
		}
	}
	for _, group := range []struct {
		name  string
		items []map[string]any
	}{{"认证记录", a.Auth}, {"开放端口", a.OpenPorts}, {"请求参数", a.Params}} {
		for i, item := range group.items {
			keys := []string{}
			for key := range item {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			lines := []string{}
			for _, key := range keys {
				switch value := item[key].(type) {
				case string:
					lines = append(lines, key+"："+value)
				case float64, bool:
					lines = append(lines, fmt.Sprint(key, "：", value))
				}
			}
			v.Articles = append(v.Articles, teamContentArticle{ID: fmt.Sprint(group.name, i), Title: group.name, Text: strings.Join(lines, "\n")})
		}
	}
	v.Total = len(v.Articles)
	v.Page = 1
	v.PageSize = max(1, v.Total)
	return nil
}

// Reports count only this task's assets, not the entire instance's asset store.
func (s *Server) taskReportMarkdown(t *Task) (string, error) {
	findings, err := t.Store.ListByKind(db.KindFinding, 100000)
	if err != nil {
		return "", err
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return "", err
	}
	counts, err := s.m.Assets().CountsByTypeForTask(id)
	if err != nil {
		return "", err
	}
	// Stable ordering is provided by report.Markdown; no state is changed here.
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return report.Markdown(report.Input{Title: contentFirst(t.Name, t.Description), Goal: t.Goal, GeneratedAt: time.Now(), AssetCounts: counts, Findings: findings}), nil
}
