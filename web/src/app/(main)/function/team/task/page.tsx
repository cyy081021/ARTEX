"use client";

import * as React from "react";
import { useSearchParams } from "next/navigation";
import { http } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { StatusBadge } from "@/components/status-badge";
import { TabsContent } from "@/components/ui/tabs";
import { TaskDetailFrame, taskDetailTabs } from "@/components/task-detail-frame";
import { TaskDetailViews } from "../../tasks/detail/task-detail-views";
import { FindingDetailContent } from "../../findings/detail/finding-detail-content";
import { MemberTaskViewProvider } from "@/lib/task-view-context";
import { ExecutionPanel } from "../execution-panel";

type Task = { id: number; name: string; kind: string; goal: string; status: string; paused: boolean; queued: boolean; created_at: string; completed_at?: string; coverage_enabled?: boolean };
type Member = { id: number; login: string; revoked: boolean };
type Detail = { task: Task; permissions: { read: boolean; execute: boolean; manage: boolean; review: boolean }; is_admin: boolean; member_id: number };
function message(error: unknown) { return error instanceof Error ? error.message : "读取失败"; }
function isAccessError(error: unknown) { const status = (error as { status?: number })?.status; return status === 401 || status === 403 || status === 404; }

function TeamTaskDetail() {
  const params = useSearchParams();
  const team = params.get("team") ?? "";
  const id = params.get("id") ?? "";
  const [detail, setDetail] = React.useState<Detail | null>(null);
  const [members, setMembers] = React.useState<Member[]>([]);
  const [dataScope, setDataScope] = React.useState("");
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const requestedTab = params.get("tab") ?? "sessions";
  const [selectedTab, setSelectedTab] = React.useState(requestedTab);
  React.useEffect(() => setSelectedTab(requestedTab), [requestedTab, team, id]);
  const findingID = params.get("finding") ?? "";
  const activeScope = `${team}:${id}`;

  React.useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const scope = `${team}:${id}`;
    setDetail(null); setMembers([]); setDataScope(""); setError(""); setLoading(true);
    const validID = (value: string) => /^\d+$/.test(value) && Number.isSafeInteger(Number(value)) && Number(value) > 0;
    if (!validID(team) || !validID(id)) { setError("团队或任务编号无效。"); setLoading(false); return; }
    const load = async () => {
      try {
        const [d, m] = await Promise.all([
          http<Detail>(`/teams/${encodeURIComponent(team)}/tasks/${encodeURIComponent(id)}`),
          http<Member[]>(`/teams/${encodeURIComponent(team)}/members`),
        ]);
        if (!alive) return;
        setDetail(d); setMembers(m ?? []); setDataScope(scope); setError("");
      } catch (e) {
        if (!alive) return;
        setError(message(e));
        if (isAccessError(e)) { setDetail(null); setMembers([]); setDataScope(""); }
      } finally {
        if (alive) { setLoading(false); timer = setTimeout(load, 5000); }
      }
    };
    setLoading(true); void load();
    return () => { alive = false; clearTimeout(timer); };
  }, [team, id]);

  const currentDetail = dataScope === activeScope ? detail : null;
  const task = currentDetail?.task;
  const tabs = [...taskDetailTabs(task?.kind), {value: "execution", label: "协作进度 / 执行"}, {value: "review", label: "复核与记录"}];
  const activeTab = tabs.some((t) => t.value === selectedTab) ? selectedTab : "sessions";
  const base = `/function/team/task/?team=${encodeURIComponent(team)}&id=${encodeURIComponent(id)}`;
  const accessLost = React.useCallback(() => { setDetail(null); setDataScope(""); setError("当前账号已失去此任务的查看权限。"); }, []);
  if (!task || !currentDetail) return <main className="p-6 text-sm">{error ? <p role="alert">{error}</p> : <p role="status">正在读取任务…</p>}</main>;
  return <MemberTaskViewProvider key={activeScope} team={team} task={id} onAccessLost={accessLost}>
    <TaskDetailFrame task={task} tab={activeTab} onTabChange={(tab) => {
      setSelectedTab(tab);
      window.history.replaceState(null, "", `${base}&tab=${encodeURIComponent(tab)}`);
    }} backHref={`/function/team/?team=${encodeURIComponent(team)}`} tabs={tabs} actions={<><Badge variant="outline">{task.kind === "reverse" ? "逆向" : "渗透"}</Badge><StatusBadge domain="task" value={task.paused ? "paused" : task.status} dot /></>}>
      <div className="flex-1 p-4 lg:p-6">
        {error && <p role="alert" className="mb-4 text-sm text-destructive">{error}</p>}
        {findingID && activeTab === "findings" ? <TabsContent value="findings" className="mt-0"><FindingDetailContent key={findingID} findingId={findingID} contextTaskId={id} /></TabsContent> : <TaskDetailViews taskId={id} kind={task.kind} paused={task.paused} coverageEnabled={task.coverage_enabled !== false} />}
        {(["sessions", "execution", "review"] as const).map((view) => <TabsContent key={view} value={view} className="mt-0"><ExecutionPanel team={team} tasks={[{id:task.id, name:task.name, kind:task.kind}]} members={members} memberID={currentDetail.member_id} admin={currentDetail.is_admin} initialTaskID={id} lockTaskSelection viewMode={view === "sessions" ? "session" : view} /></TabsContent>)}
      </div>
    </TaskDetailFrame>
  </MemberTaskViewProvider>;
}

export default function TeamTaskPage() {
  return <React.Suspense fallback={<main className="p-6 text-sm text-muted-foreground">正在打开团队任务…</main>}><TeamTaskDetail /></React.Suspense>;
}
