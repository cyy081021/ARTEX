"use client";

import * as React from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { TeamSessionWorkspace } from "@/components/team-shared-messages";
import { http } from "@/lib/api";
import { branchSnapshotRequests, projectBranchEvents } from "./team-branch-messages-state.mjs";

type Branch = {
  id: number;
  owner_id: number;
  control_id: number;
  device_id: number;
  state: string;
  review_mode?: "automatic" | "manual";
  review_reason?: string;
  spec: { title: string; question: string; coordinator?: boolean; kind: string };
  units: { id: number; state: string; result?: { summary: string; outcome: string } }[];
};
type Event = { id: number; branch_id: number; kind: string; text: string; member_id?: number; device_id?: number; created_at: string };
type Snapshot = {
  project: { state: string; branches: Branch[]; policy: { auto_dispatch?: boolean; auto_review?: boolean } };
  permissions: string[];
  events: Event[];
  cursor: number;
  has_more: boolean;
};

const visibleKinds = new Set(["plan", "message", "guidance", "submitted", "auto_review", "review_required", "review"]);
const branchStates: Record<string, string> = { waiting_ready: "等待设备", waiting_dependency: "等待依赖", running: "执行中", paused: "已暂停", review_pending: "待人工复审", accepted: "已接收", needs_supplement: "待补充", failed: "失败", cancelled: "已停止" };
const eventNames: Record<string, string> = { plan: "工作计划", message: "讨论", guidance: "执行指导", submitted: "提交核验", auto_review: "自动核验", review_required: "转人工复审", review: "复核结果" };
function requestID() { return globalThis.crypto?.randomUUID?.() ?? `branch-guide-${Date.now()}-${Math.random().toString(36).slice(2)}`; }
function statusCode(error: unknown) { return (error as { status?: number } | null)?.status; }
function preferredBranch(branches: Branch[]) { return [...branches].sort((a, b) => Number(!!b.spec.coordinator) - Number(!!a.spec.coordinator) || b.id - a.id)[0]; }

export function TeamBranchMessages({ team, taskId, memberID, admin }: { team: string; taskId: string; memberID: number; admin: boolean }) {
  const base = `/teams/${encodeURIComponent(team)}/tasks/${encodeURIComponent(taskId)}/branches`;
  const scope = `${team}:${taskId}`;
  const scopeRef = React.useRef(scope);
  const cursorByBranch = React.useRef(new Map<number, number>());
  const eventCache = React.useRef(new Map<number, Event[]>());
  const [snapshot, setSnapshot] = React.useState<Snapshot | null>(null);
  const [selected, setSelected] = React.useState(0);
  const [events, setEvents] = React.useState<Event[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [notice, setNotice] = React.useState("");
  const [fallback, setFallback] = React.useState(false);
  const [historyOpen, setHistoryOpen] = React.useState(false);
  const [guide, setGuide] = React.useState("");
  const [refresh, bump] = React.useReducer((value: number) => value + 1, 0);
  const branches = snapshot?.project.branches ?? [];
  const branch = branches.find((item) => item.id === selected) ?? preferredBranch(branches);
  const canGuide = !!branch && snapshot?.permissions.includes("guide") === true && (admin || (branch.control_id === memberID && memberID > 0));
  const activeForGuidance = !!branch && ["running", "waiting_ready", "waiting_dependency", "paused"].includes(branch.state);

  React.useEffect(() => { scopeRef.current = scope; cursorByBranch.current.clear(); eventCache.current.clear(); setSnapshot(null); setEvents([]); setSelected(0); setError(""); setNotice(""); setFallback(false); setLoading(true); }, [scope]);

  React.useEffect(() => {
    if (fallback) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const requestedScope = scope;
    const load = async () => {
      try {
        const head = await http<Snapshot>(`${base}?after=0&limit=1`);
        if (!alive || scopeRef.current !== requestedScope) return;
        const nextBranches = head.project?.branches ?? [];
        setSnapshot(head);
        const allowedBranchIDs = new Set(nextBranches.map((item) => item.id));
        for (const branchID of eventCache.current.keys()) if (!allowedBranchIDs.has(branchID)) eventCache.current.delete(branchID);
        for (const branchID of cursorByBranch.current.keys()) if (!allowedBranchIDs.has(branchID)) cursorByBranch.current.delete(branchID);
        if (!head.permissions.includes("process")) {
          eventCache.current.clear(); cursorByBranch.current.clear(); setEvents([]); setError(""); return;
        }
        if (!nextBranches.length) { setEvents([]); setError(""); return; }
        if (!selected || !nextBranches.some((item) => item.id === selected)) {
          setSelected(preferredBranch(nextBranches)?.id ?? 0);
          setEvents([]);
          return;
        }
        const initialCursor = cursorByBranch.current.get(selected) ?? 0;
        const requests = branchSnapshotRequests(base, selected, initialCursor, head.permissions);
        if (!requests.events) { eventCache.current.clear(); cursorByBranch.current.clear(); setEvents([]); return; }
        let page = await http<Snapshot>(requests.events);
        const collected: Event[] = [];
        let safety = 0;
        let cursor = initialCursor;
        while (alive && scopeRef.current === requestedScope) {
          collected.push(...(page.events ?? []));
          const nextCursor = page.cursor ?? 0;
          if (!page.has_more || nextCursor <= cursor || ++safety >= 1000) { cursor = Math.max(cursor, nextCursor); break; }
          cursor = nextCursor;
          const nextRequests = branchSnapshotRequests(base, selected, cursor, head.permissions);
          if (!nextRequests.events) break;
          page = await http<Snapshot>(nextRequests.events);
        }
        if (!alive || scopeRef.current !== requestedScope) return;
        cursorByBranch.current.set(selected, cursor);
        const merged = projectBranchEvents(eventCache.current.get(selected) ?? [], collected, selected, visibleKinds, head.permissions);
        eventCache.current.set(selected, merged);
        setEvents(merged);
        setError("");
      } catch (e) {
        if (!alive || scopeRef.current !== requestedScope) return;
        if (statusCode(e) === 404) { eventCache.current.clear(); cursorByBranch.current.clear(); setFallback(true); setSnapshot(null); setEvents([]); }
        else if (statusCode(e) === 401 || statusCode(e) === 403) {
          eventCache.current.clear(); cursorByBranch.current.clear(); setEvents([]);
          setSnapshot(null);
          setError(statusCode(e) === 403 ? "过程权限已收回；当前仅显示只读分支状态。" : "当前账号无权查看分支消息。");
        }
        else setError(`分支消息读取失败：${(e as Error).message}`);
      } finally {
        if (alive && scopeRef.current === requestedScope) { setLoading(false); timer = setTimeout(load, 2500); }
      }
    };
    setLoading(true);
    void load();
    return () => { alive = false; clearTimeout(timer); };
  }, [base, scope, selected, refresh, fallback]);

  async function sendGuide(event: React.FormEvent) {
    event.preventDefault();
    const text = guide.trim();
    if (!branch || !canGuide || !activeForGuidance || !text || busy) return;
    const requestedScope = scope;
    setBusy(true); setError(""); setNotice("");
    try {
      await http(`${base}/command`, { method: "POST", body: JSON.stringify({ type: "guide", request_id: requestID(), branch_id: branch.id, text }) });
      if (scopeRef.current !== requestedScope) return;
      setGuide("");
      setNotice("指导已记录；执行端会在下一工具边界应用提示。实际效果待后续状态确认。");
      bump();
    } catch (e) {
      if (scopeRef.current !== requestedScope) return;
      if (statusCode(e) === 403) { setError("当前账号无权发送此分支指导。"); }
      else setError(`指导未发送：${(e as Error).message}`);
    } finally { if (scopeRef.current === requestedScope) setBusy(false); }
  }

  if (fallback) return <section className="space-y-3"><TeamSessionWorkspace team={team} taskId={taskId} /></section>;
  if (error && !snapshot) return <section className="space-y-3 rounded-md border p-3"><p role="alert" className="text-sm text-destructive">{error}</p><Button variant="outline" size="sm" disabled={loading} onClick={() => { setFallback(false); bump(); }}>重新读取</Button></section>;
  const results = branch?.units.filter((unit) => unit.result?.summary) ?? [];

  return <section className="space-y-3 rounded-md border p-3" aria-label="分支协作会话">
    <div className="flex flex-wrap items-center justify-between gap-2"><div><h3 className="font-medium">分支会话</h3><p className="text-xs text-muted-foreground">主任务保持原流程验收；明确结果可自动接收，不明确结果转人工复审。</p></div><Button size="sm" variant="outline" disabled={loading} onClick={() => bump()}>刷新</Button></div>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}{snapshot && !snapshot.permissions.includes("process") && <p className="text-xs text-muted-foreground">当前为只读视图，分支过程消息不可见。</p>}{notice && <p role="status" className="text-sm text-muted-foreground">{notice}</p>}
    <div className="grid min-h-72 gap-3 md:grid-cols-[minmax(14rem,0.32fr)_minmax(0,1fr)]">
      <aside className="space-y-1 rounded-md bg-muted/30 p-2" aria-label="分支列表"><h4 className="px-2 py-1 text-sm font-medium">工作分支</h4>{branches.map((item) => <button key={item.id} type="button" aria-pressed={item.id === (branch?.id ?? 0)} className={`w-full rounded-md border p-2 text-left text-sm ${item.id === branch?.id ? "bg-background shadow-sm" : "border-transparent hover:bg-background/70"}`} onClick={() => { setSelected(item.id); setEvents(eventCache.current.get(item.id) ?? []); }}><span className="block font-medium">{item.spec.coordinator ? "协调器 · " : ""}{item.spec.title}</span><span className="block text-xs text-muted-foreground">分支 #{item.id} · 设备 #{item.device_id} · {branchStates[item.state] ?? item.state}</span></button>)}{!branches.length && <p className="px-2 py-3 text-xs text-muted-foreground">尚无已分配的工作分支。</p>}</aside>
      <div className="min-w-0 space-y-3 rounded-md border p-3">
        {branch ? <>
          <div><div className="flex flex-wrap items-center gap-2"><h4 className="font-medium">{branch.spec.title}</h4><Badge variant="outline">分支 #{branch.id}</Badge><Badge variant="secondary">{branchStates[branch.state] ?? branch.state}</Badge></div><p className="mt-1 text-xs text-muted-foreground">设备 #{branch.device_id} · {branch.spec.question}</p>{branch.review_reason && <p className="mt-2 text-xs text-muted-foreground">核验说明：{branch.review_reason}</p>}</div>
          {canGuide && activeForGuidance && <form className="space-y-2 rounded-md bg-muted/40 p-2" onSubmit={(event) => void sendGuide(event)}><label className="text-sm font-medium" htmlFor={`branch-guide-${taskId}-${branch.id}`}>发送执行指导</label><Textarea id={`branch-guide-${taskId}-${branch.id}`} value={guide} onChange={(event) => setGuide(event.target.value)} maxLength={4096} rows={2} disabled={busy} placeholder="指导会在执行端下一工具边界应用" /><Button size="sm" disabled={busy || !guide.trim()}>{busy ? "发送中…" : "发送指导"}</Button></form>}
          {branch && !canGuide && <p className="text-xs text-muted-foreground">当前账号没有此分支的指导权限。</p>}
          {canGuide && !activeForGuidance && <p className="text-xs text-muted-foreground">当前分支状态不接受新指导。</p>}
          <div className="max-h-[32rem] space-y-2 overflow-y-auto" aria-live="polite">{loading && !events.length && <p className="text-xs text-muted-foreground">正在读取分支消息…</p>}{events.map((item) => <article key={item.id} className="rounded-md border p-2"><div className="flex flex-wrap justify-between gap-2 text-xs text-muted-foreground"><span>{eventNames[item.kind] ?? "分支消息"}{item.member_id ? ` · 成员 #${item.member_id}` : item.device_id ? ` · 设备 #${item.device_id}` : ""}</span><time>{item.created_at ? new Date(item.created_at).toLocaleString() : ""}</time></div><p className="mt-1 whitespace-pre-wrap break-words text-sm">{item.text}</p></article>)}{results.map((unit) => <article key={`unit-${unit.id}`} className="rounded-md border bg-muted/30 p-2"><p className="text-xs text-muted-foreground">工作结果摘要 · 工作单 #{unit.id} · {unit.state}</p><p className="mt-1 whitespace-pre-wrap text-sm">{unit.result?.summary}</p></article>)}{!loading && !events.length && !results.length && <p className="text-sm text-muted-foreground">暂无可显示的计划、讨论或结果摘要。</p>}</div>
        </> : <p className="text-sm text-muted-foreground">尚无分支消息。协作开始并分配工作后，消息会出现在这里。</p>}
      </div>
    </div>
    <details className="rounded-md border p-3" onToggle={(event) => setHistoryOpen(event.currentTarget.open)}><summary className="cursor-pointer text-sm font-medium">查看主任务会话历史</summary>{historyOpen && <div className="mt-3"><TeamSessionWorkspace team={team} taskId={taskId} /></div>}</details>
  </section>;
}
