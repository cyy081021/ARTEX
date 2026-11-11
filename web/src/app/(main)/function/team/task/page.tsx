"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { http } from "@/lib/api";
import { teamSessionStateLabel } from "@/lib/team-session-display";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ExecutionPanel } from "../execution-panel";

type Task = { id: number; name: string; kind: string; goal: string; status: string; paused: boolean; queued: boolean; created_at: string; completed_at?: string };
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
  return <main className="space-y-5 p-4 md:p-6">
    <div><Link className="inline-flex min-h-11 items-center text-sm underline" href={`/function/team/?team=${encodeURIComponent(team)}`}>← 返回团队协作</Link><h1 className="mt-2 text-2xl font-semibold">成员任务详情</h1></div>
    {error && <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">任务状态读取失败：{error}{!currentDetail ? " 当前账号可能已失去访问权限。" : ""}</p>}
    {loading && !task && <p role="status" className="text-sm text-muted-foreground">正在读取任务和协作权限…</p>}
    {task && currentDetail && <>
      <Card><CardHeader><CardTitle>{task.name || `任务 ${task.id}`}</CardTitle><p className="text-sm text-muted-foreground">任务 #{task.id} · {task.kind === "reverse" ? "逆向" : task.kind === "pentest" ? "渗透" : task.kind}</p></CardHeader><CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2"><Badge variant="outline">{teamSessionStateLabel(task.status)}</Badge>{task.paused && task.status !== "paused" && <Badge variant="outline">已暂停</Badge>}{task.queued && <Badge variant="outline">排队中</Badge>}</div>
        <div><h2 className="font-medium">任务目标</h2><p className="mt-1 whitespace-pre-wrap break-words text-sm">{task.goal || "未提供任务目标。"}</p></div>
        <div><h2 className="font-medium">当前授权</h2><p className="mt-1 text-sm">{[["查看", currentDetail.permissions.read], ["执行", currentDetail.permissions.execute], ["管理", currentDetail.permissions.manage], ["复核", currentDetail.permissions.review]].map(([name, allowed]) => `${name}：${allowed ? "允许" : "未授权"}`).join(" · ")}</p></div>
        <p className="text-xs text-muted-foreground">创建：{task.created_at ? new Date(task.created_at).toLocaleString() : "未知"}{task.completed_at ? ` · 完成：${new Date(task.completed_at).toLocaleString()}` : ""}</p>
      </CardContent></Card>
      <ExecutionPanel key={`${team}:${id}`} team={team} tasks={[{ id: task.id, name: task.name, kind: task.kind }]} members={members} memberID={currentDetail.member_id} admin={currentDetail.is_admin} initialTaskID={id} lockTaskSelection />
    </>}
  </main>;
}

export default function TeamTaskPage() {
  return <React.Suspense fallback={<main className="p-6 text-sm text-muted-foreground">正在打开团队任务…</main>}><TeamTaskDetail /></React.Suspense>;
}
