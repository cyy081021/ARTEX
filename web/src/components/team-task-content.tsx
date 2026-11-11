"use client";

import * as React from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { http } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { acceptsTeamTaskResponse, matchesTeamTaskScope } from "@/lib/team-task-content-state.mjs";

export type TeamTaskSection = "overview" | "graph" | "broadcast" | "findings" | "finding-relations" | "retests" | "assets" | "coverage" | "intercept" | "report" | "workflow-requests" | "reverse";
export type TeamTaskContent = {
  section: string; title: string; summary?: { label: string; value: string }[];
  columns?: { key: string; label: string }[];
  rows?: { id: string; cells: Record<string, string>; detail?: string }[];
  articles?: { id: string; title: string; meta?: string; text: string; format?: "markdown" }[];
  graph?: { nodes: { id: string; label: string; kind: string; status?: string; detail?: string }[]; edges: { source: string; target: string; label?: string }[] };
  page: number; page_size: number; total: number; has_more: boolean;
};

export const TEAM_TASK_SECTIONS: { id: TeamTaskSection; title: string }[] = [
  { id: "overview", title: "总览" }, { id: "graph", title: "探索链路" }, { id: "broadcast", title: "播报板" },
  { id: "findings", title: "发现" }, { id: "finding-relations", title: "漏洞关联" }, { id: "retests", title: "复测" },
  { id: "assets", title: "测试资产" }, { id: "coverage", title: "资产覆盖图" }, { id: "intercept", title: "拦截审批" },
  { id: "report", title: "报告" }, { id: "workflow-requests", title: "跨流程协助" }, { id: "reverse", title: "分析档案" },
];

function friendlyError(error: unknown) {
  const status = (error as { status?: number })?.status;
  if (status === 401) return "登录状态已失效，请重新登录后查看。";
  if (status === 403) return "当前账号没有此任务的查看权限，或任务尚未共享给团队。";
  if (status === 404) return "任务或内容已不存在，或已从团队共享中移除。";
  return error instanceof Error ? error.message : "读取任务内容失败，请稍后重试。";
}

function graphLayout(content: TeamTaskContent, query: string): { nodes: Node[]; edges: Edge[] } {
  const sourceGraph = content.graph;
  const needle = query.trim().toLocaleLowerCase();
  const graph = sourceGraph && needle ? (() => {
    const nodes = sourceGraph.nodes.filter((node) => `${node.label} ${node.kind} ${node.status ?? ""} ${node.detail ?? ""}`.toLocaleLowerCase().includes(needle));
    const nodeIDs = new Set(nodes.map((node) => node.id));
    const edges = sourceGraph.edges.filter((edge) => nodeIDs.has(edge.source) && nodeIDs.has(edge.target));
    return { nodes, edges };
  })() : sourceGraph;
  if (!graph) return { nodes: [], edges: [] };
  const depth = new Map<string, number>();
  const outgoing = new Map<string, string[]>();
  const incoming = new Set<string>();
  for (const edge of graph.edges) {
    outgoing.set(edge.source, [...(outgoing.get(edge.source) ?? []), edge.target]);
    incoming.add(edge.target);
  }
  const queue = graph.nodes.filter((node) => !incoming.has(node.id)).map((node) => node.id);
  const visited = new Set(queue);
  queue.forEach((id) => depth.set(id, 0));
  for (let cursor = 0; cursor < queue.length; cursor++) {
    const source = queue[cursor];
    for (const target of outgoing.get(source) ?? []) {
      if (visited.has(target)) continue;
      visited.add(target);
      depth.set(target, Math.min((depth.get(source) ?? 0) + 1, 8));
      queue.push(target);
    }
  }
  graph.nodes.forEach((node) => { if (!depth.has(node.id)) depth.set(node.id, 0); });
  const index = new Map<number, number>();
  const nodes = graph.nodes.map((node) => {
    const col = depth.get(node.id) ?? 0;
    const row = index.get(col) ?? 0;
    index.set(col, row + 1);
    return { id: node.id, position: { x: col * 250, y: row * 118 }, data: { label: <div className="max-w-52"><div className="text-xs text-muted-foreground">{node.kind}{node.status ? ` · ${node.status}` : ""}</div><div className="truncate text-sm font-medium">{node.label || node.id}</div></div> }, style: { width: 210, borderRadius: 8, border: "1px solid var(--border)", background: "var(--card)", color: "var(--card-foreground)", padding: 10 } } satisfies Node;
  });
  const edges = graph.edges.map((edge, i) => ({ id: `e-${i}-${edge.source}-${edge.target}`, source: edge.source, target: edge.target, label: edge.label, type: "smoothstep", animated: false })) satisfies Edge[];
  return { nodes, edges };
}

function TableView({ content, onDetail }: { content: TeamTaskContent; onDetail: (key: string) => void }) {
  if (!content.rows?.length) return <p className="p-4 text-sm text-muted-foreground">当前没有可显示的记录。</p>;
  const columns = content.columns ?? Object.keys(content.rows[0].cells).map((key) => ({ key, label: key }));
  return <div className="overflow-x-auto"><table className="w-full min-w-[640px] border-collapse text-left text-sm"><thead><tr className="border-b text-muted-foreground">{columns.map((col) => <th key={col.key} className="px-3 py-2 font-medium">{col.label}</th>)}<th className="px-3 py-2" /></tr></thead><tbody>{content.rows.map((row) => <tr key={row.id} className="border-b last:border-0">{columns.map((col) => {
    const value = row.cells[col.key] || "—";
    const long = value.length > 180;
    return <td key={col.key} className="max-w-[28rem] px-3 py-3 align-top"><div className={`break-words ${long ? "line-clamp-3" : ""}`}>{value}</div>{long && <details className="mt-1 text-xs"><summary className="cursor-pointer text-primary">展开全文</summary><p className="mt-1 max-h-48 overflow-y-auto whitespace-pre-wrap break-words text-sm">{value}</p></details>}</td>;
  })}<td className="px-3 py-3 text-right align-top">{row.detail && <Button variant="outline" size="sm" onClick={() => onDetail(row.detail!)}>查看详情</Button>}</td></tr>)}</tbody></table></div>;
}

function ContentBody({ content, onDetail, search }: { content: TeamTaskContent; onDetail: (key: string) => void; search: string }) {
  const [selected, setSelected] = React.useState<{ id: string; title: string; meta?: string; text: string } | null>(null);
  const flow = React.useMemo(() => graphLayout(content, search), [content, search]);
  const hasTable = Boolean(content.rows?.length || content.columns?.length);
  const visibleGraphNodes = React.useMemo(() => {
    const needle = search.trim().toLocaleLowerCase();
    return content.graph?.nodes.filter((node) => !needle || `${node.label} ${node.kind} ${node.status ?? ""} ${node.detail ?? ""}`.toLocaleLowerCase().includes(needle)) ?? [];
  }, [content.graph, search]);
  const pickNode = React.useCallback((_event: React.MouseEvent, node: Node) => {
    const source = content.graph?.nodes.find((item) => item.id === node.id);
    if (source) setSelected({ id: source.id, title: source.label || source.id, meta: `${source.kind}${source.status ? ` · ${source.status}` : ""}`, text: source.detail || "暂无更多详情。" });
  }, [content.graph]);
  return <>
    {content.summary && content.summary.length > 0 && <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{content.summary.map((item) => <Card key={item.label}><CardContent className="p-4"><div className="text-xs text-muted-foreground">{item.label}</div><div className="mt-1 break-words text-lg font-semibold">{item.value}</div></CardContent></Card>)}</div>}
    {content.graph && <><div className="h-[min(62vh,620px)] min-h-80 overflow-hidden rounded-md border">{content.graph.nodes.length === 0 ? <div className="flex h-full items-center justify-center text-sm text-muted-foreground">此栏目暂无节点。</div> : flow.nodes.length === 0 ? <div className="flex h-full items-center justify-center text-sm text-muted-foreground">没有匹配“{search}”的节点。</div> : <ReactFlow nodes={flow.nodes} edges={flow.edges} onNodeClick={pickNode} fitView fitViewOptions={{ padding: 0.2 }} nodesDraggable={false} nodesConnectable={false} elementsSelectable zoomOnDoubleClick={false}><Background color="var(--border)" /><Controls showInteractive={false} /><MiniMap pannable zoomable nodeColor="var(--muted-foreground)" /></ReactFlow>}</div>{selected && <Card className="mt-3 border-primary/40"><CardHeader><CardTitle className="text-base">{selected.title}</CardTitle>{selected.meta && <p className="text-xs text-muted-foreground">{selected.meta}</p>}</CardHeader><CardContent><pre className="max-h-48 overflow-y-auto whitespace-pre-wrap break-words font-sans text-sm">{selected.text}</pre></CardContent></Card>}<details className="mt-3 rounded-md border"><summary className="cursor-pointer px-3 py-2 text-sm font-medium">节点列表（{visibleGraphNodes.length}）</summary><div className="grid max-h-80 gap-2 overflow-y-auto p-3 sm:grid-cols-2">{visibleGraphNodes.map((node) => <button key={node.id} type="button" className="rounded-md border p-3 text-left hover:bg-muted/50" onClick={() => setSelected({ id: node.id, title: node.label || node.id, meta: `${node.kind}${node.status ? ` · ${node.status}` : ""}`, text: node.detail || "暂无更多详情。" })}><div className="text-xs text-muted-foreground">{node.kind} · {node.status || "未标注状态"}</div><div className="mt-1 font-medium">{node.label || node.id}</div></button>)}</div></details></>}
    {hasTable && <TableView content={content} onDetail={onDetail} />}
    {content.articles?.map((article) => <Card key={article.id}><CardHeader><CardTitle className="text-base">{article.title}</CardTitle>{article.meta && <p className="text-xs text-muted-foreground">{article.meta}</p>}</CardHeader><CardContent>{article.format === "markdown" ? <div className="prose prose-sm max-w-none dark:prose-invert"><ReactMarkdown remarkPlugins={[remarkGfm]}>{article.text}</ReactMarkdown></div> : <pre className="whitespace-pre-wrap break-words font-sans text-sm">{article.text}</pre>}</CardContent></Card>)}
    {!content.summary?.length && !content.graph && !hasTable && !content.articles?.length && <p className="p-4 text-sm text-muted-foreground">当前没有可显示的内容。</p>}
  </>;
}

export function TeamTaskContentPanel({ team, task, section }: { team: string; task: string; section: TeamTaskSection }) {
  const [content, setContent] = React.useState<TeamTaskContent | null>(null);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const [page, setPage] = React.useState(1);
  const [query, setQuery] = React.useState("");
  const [detailKey, setDetailKey] = React.useState("");
  const [refreshTick, setRefreshTick] = React.useState(0);
  const scope = `${team}:${task}:${section}:${detailKey}:${page}:${query}`;
  const requestID = React.useRef(0);
  const latestScope = React.useRef(scope);
  latestScope.current = scope;
  const [dataScope, setDataScope] = React.useState("");
  const sectionTitle = TEAM_TASK_SECTIONS.find((item) => item.id === section)?.title ?? "任务内容";
  const currentContent = matchesTeamTaskScope(dataScope, scope) ? content : null;

  React.useEffect(() => { setContent(null); setDataScope(""); setError(""); setLoading(true); setPage(1); setDetailKey(""); setQuery(""); }, [team, task, section]);
  React.useEffect(() => {
    let alive = true;
    const currentID = ++requestID.current;
    const currentScope = scope;
    const load = async () => {
      setLoading(true);
      setError("");
      const viewKey = detailKey ? detailKey.split("/").map(encodeURIComponent).join("/") : encodeURIComponent(section);
      const search = new URLSearchParams();
      if (!detailKey) { search.set("page", String(page)); search.set("size", "50"); if (query.trim()) search.set("q", query.trim()); }
      const url = `/teams/${encodeURIComponent(team)}/tasks/${encodeURIComponent(task)}/view/${viewKey}${search.size ? `?${search}` : ""}`;
      try {
        const result = await http<TeamTaskContent>(url);
        if (!alive || !acceptsTeamTaskResponse(currentScope, latestScope.current, currentID, requestID.current)) return;
        setContent(result); setDataScope(currentScope); setError("");
      } catch (cause) {
        if (!alive || !acceptsTeamTaskResponse(currentScope, latestScope.current, currentID, requestID.current)) return;
        setError(friendlyError(cause));
        const status = (cause as { status?: number })?.status;
        if (status === 401 || status === 403 || status === 404) { setContent(null); setDataScope(""); }
      } finally {
        if (alive && acceptsTeamTaskResponse(currentScope, latestScope.current, currentID, requestID.current)) setLoading(false);
      }
    };
    void load();
    const timer = window.setInterval(() => setRefreshTick((v) => v + 1), 10_000);
    return () => { alive = false; window.clearInterval(timer); };
  }, [team, task, section, detailKey, page, query, refreshTick]);

  const onDetail = (key: string) => { setDetailKey(key.replace(/^\/+/, "")); setQuery(""); setContent(null); setDataScope(""); };
  const returnToList = () => { setDetailKey(""); setPage(1); setQuery(""); setContent(null); setDataScope(""); };
  const canPage = currentContent && (page > 1 || currentContent.has_more || currentContent.total > page * (currentContent.page_size || 50));
  return <section className="space-y-4">
    <Card><CardHeader className="flex flex-row flex-wrap items-center justify-between gap-3"><div><CardTitle>{detailKey ? <button className="text-sm underline" onClick={returnToList}>← 返回{sectionTitle}</button> : currentContent?.title || sectionTitle}</CardTitle>{currentContent && <p className="mt-1 text-xs text-muted-foreground">{currentContent.graph ? `${currentContent.graph.nodes.length} 个节点 · ${currentContent.graph.edges.length} 条关系` : `共 ${currentContent.total} 条`}</p>}</div><div className="flex items-center gap-2">{!detailKey && <Input aria-label="搜索当前栏目" placeholder="搜索" value={query} onChange={(e) => { setQuery(e.target.value); setPage(1); }} className="w-44" />}<Button variant="outline" size="sm" onClick={() => setRefreshTick((v) => v + 1)}>刷新</Button></div></CardHeader><CardContent className="space-y-4">
      {error && <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">内容读取失败：{error}</p>}
      {(loading || !currentContent && !error) && <p role="status" className="text-sm text-muted-foreground">正在读取…</p>}
      {currentContent && <ContentBody key={scope} content={currentContent} onDetail={onDetail} search={query} />}
      {canPage && !detailKey && <div className="flex items-center justify-between border-t pt-3"><Button variant="outline" size="sm" disabled={page <= 1 || loading} onClick={() => setPage((n) => Math.max(1, n - 1))}>上一页</Button><span className="text-sm text-muted-foreground">第 {page} 页</span><Button variant="outline" size="sm" disabled={!currentContent?.has_more && currentContent && currentContent.total <= page * (currentContent.page_size || 50) || loading} onClick={() => setPage((n) => n + 1)}>下一页</Button></div>}
    </CardContent></Card>
  </section>;
}
