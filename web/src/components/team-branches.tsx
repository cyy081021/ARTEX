"use client";

import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { http } from "@/lib/api";
import { TeamBranchSetup } from "@/components/team-branch-setup";

type Member = { id: number; login: string; revoked?: boolean };
type Device = {
  id: number;
  name: string;
  owner_member_id: number;
  revoked: boolean;
  capabilities?: {
    roles?: string[];
    execution_enabled?: boolean;
    runtime_profiles?: { id: string; name: string; platform: string; digest: string; max_duration_ms: number }[];
  };
};
type Material = { id: string; name: string; size: number; sha256: string };
type BranchAsset = { id: string; target: string; version: string };
type BranchPolicy = {
  goal: string;
  budget: number;
  max_tool_seconds: number;
  min_tool_interval_ms: number;
  auto_dispatch?: boolean;
  auto_publish: boolean;
  auto_review?: boolean;
  kinds: string[];
  assets: BranchAsset[];
  materials: Material[];
};
type BranchUnit = {
  id: number;
  spec: {
    key: string;
    question: string;
    role: string;
    material_hashes?: string[];
    runtime?: { id: string; name: string; platform: string; digest: string; max_duration_ms: number; artifact_hashes: string[] };
  };
  state: string;
  attempt: number;
  evidence_version?: string;
  result?: { outcome: string; summary: string; evidence?: { tool: string; sha256: string; content: string }[] };
};
type Branch = {
  id: number;
  work_id: number;
  task_id: number;
  owner_id: number;
  control_id: number;
  device_id: number;
  epoch: number;
  revision: number;
  state: string;
  reason?: string;
  review_mode?: "automatic" | "manual";
  review_reason?: string;
  spent: number;
  spec: {
    title: string;
    question: string;
    kind: string;
    budget: number;
    roles: string[];
    restricted: boolean;
    members?: number[];
    asset_ids: string[];
    material_hashes: string[];
    depends_on?: number[];
  };
  contributors: number[];
  units: BranchUnit[];
  guidance?: { id: number; text: string; status: string; member_id: number; epoch: number }[];
};
type PoolWork = {
  id: number;
  spec: {
    title: string;
    question: string;
    kind: string;
    budget: number;
    coordinator?: boolean;
    restricted: boolean;
    members?: number[];
    asset_ids: string[];
    material_hashes: string[];
  };
  state: string;
  branch_id?: number;
  created_by: number;
};
type BranchEvent = {
  id: number;
  branch_id: number;
  unit_id?: number;
  epoch?: number;
  seq?: number;
  kind: string;
  text: string;
  member_id?: number;
  device_id?: number;
  evidence?: { tool: string; sha256: string; content: string };
  created_at: string;
};
type Snapshot = {
  project: {
    revision: number;
    cursor: number;
    policy: BranchPolicy;
    state: string;
    pool: PoolWork[];
    branches: Branch[];
    permissions?: Record<string, string[]>;
  };
  permissions: string[];
  events: BranchEvent[];
  cursor: number;
  has_more: boolean;
};
type CommandResponse = { receipt: { branch_id?: number; work_id?: number; unit_id?: number }; snapshot?: Snapshot };
type WorkspaceDevices = { devices: Device[] };
type Artifact = { id: number; name: string; size_bytes: number; sha256?: string };

const permissionNames: Record<string, string> = {
  read: "查看",
  process: "过程",
  evidence: "证据",
  discuss: "讨论",
  execute: "执行",
  guide: "指导",
  control: "控制",
  review: "复核",
  manage: "管理",
};
const stateNames: Record<string, string> = {
  waiting_ready: "等待设备就绪",
  running: "执行中",
  waiting_dependency: "等待依赖分支",
  paused: "已暂停",
  pausing: "等待当前操作结束",
  review_pending: "等待独立复核",
  needs_supplement: "需要补充",
  accepted: "已通过独立复核",
  cancelled: "已停止",
  failed: "失败",
  transfer_wait: "等待安全交接",
  proposed: "待管理员批准",
  published: "可领取",
  claimed: "已领取",
  complete: "全部已复核",
  partial: "部分完成",
};
const kindName = (kind: string) => (kind === "reverse" ? "逆向" : "渗透");
const branchStateName = (branch: Branch) => branch.review_mode === "automatic" && branch.state === "accepted" ? "自动接收" : branch.review_mode === "automatic" && branch.state === "review_pending" ? "待人工复审" : stateNames[branch.state] ?? branch.state;
const commandPath = (team: string, taskId: number) => `/teams/${team}/tasks/${taskId}/branches/command`;
const branchPath = (team: string, taskId: number) => `/teams/${team}/tasks/${taskId}/branches`;
const controlClass = "min-h-10 w-full rounded-md border bg-background px-3 py-2 text-sm";
const newRequestID = () => `branch-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
const branchPermissionKeys = ["read", "process", "evidence", "discuss", "execute", "guide", "control", "review", "manage"] as const;

function isPermissionDenied(error: unknown) {
  const value = error as (Error & { status?: number }) | null;
  const message = value?.message?.toLowerCase() ?? "";
  return value?.status === 401 || value?.status === 403 || message === "未授权" || message.includes("branch access denied") || message.includes("team collaboration authorization denied") || message.includes("没有此任务操作权限");
}

function isNotFound(error: unknown) {
  const value = error as (Error & { status?: number }) | null;
  return value?.status === 404 || (value?.message ?? "").includes("404");
}

function parseAssets(text: string): BranchAsset[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const sep = line.indexOf("=");
      if (sep < 1) throw new Error("每个资产请按 id=授权目标 填写，每行一个。");
      return { id: line.slice(0, sep).trim(), target: line.slice(sep + 1).trim(), version: "1" };
    });
}

function mergeSnapshots(current: Snapshot | null, incoming: Snapshot, append: boolean): Snapshot {
  const safe = normalizeSnapshot(incoming);
  const previousPermissions = new Set(current?.permissions ?? []);
  const nextPermissions = new Set(safe.permissions);
  const lostProcess = !!current && previousPermissions.has("process") && !nextPermissions.has("process");
  const lostEvidence = !!current && previousPermissions.has("evidence") && !nextPermissions.has("evidence");
  const older = append && current ? normalizeSnapshot(current).events : [];
  const byID = new Map<number, BranchEvent>();
  for (const event of [...older, ...safe.events]) byID.set(event.id, event);
  const events = lostProcess ? [] : [...byID.values()].sort((a, b) => a.id - b.id);
  if (lostEvidence) for (const event of events) delete event.evidence;
  return { ...safe, events };
}

function normalizeSnapshot(value: Snapshot): Snapshot {
  const project = value?.project ?? ({} as Snapshot["project"]);
  const branches = (project.branches ?? []).map((branch) => ({
    ...branch,
    spec: { ...branch.spec, asset_ids: branch.spec?.asset_ids ?? [], material_hashes: branch.spec?.material_hashes ?? [], roles: branch.spec?.roles ?? [], depends_on: branch.spec?.depends_on ?? [], members: branch.spec?.members ?? [] },
    units: branch.units ?? [], guidance: branch.guidance ?? [], contributors: branch.contributors ?? [],
  }));
  return {
    ...value,
    permissions: value?.permissions ?? [], events: value?.events ?? [],
    project: {
      ...project,
      permissions: project?.permissions ?? {},
      policy: { ...project.policy, materials: project.policy?.materials ?? [], assets: project.policy?.assets ?? [], kinds: project.policy?.kinds ?? [] },
      pool: project.pool ?? [], branches,
    },
  };
}

function eventTitle(event: BranchEvent, memberName: (id: number) => string, deviceName: (id: number) => string) {
  const who = event.member_id ? memberName(event.member_id) : event.device_id ? deviceName(event.device_id) : "系统";
  const labels: Record<string, string> = {
    message: "讨论",
    plan: "计划工作单",
    tool_start: "开始工具操作",
    tool_end: "结束工具操作",
    tool_error: "工具错误",
    checkpoint: "检查点",
    evidence: "候选证据",
    guidance: "发送指导",
    guidance_received: "已收到指导",
    guidance_applied: "已应用指导",
    submitted: "提交复核",
    review: "独立复核",
    runtime_authorized: "批准动态环境",
    dependency: "更新依赖",
    evidence_invalidated: "证据版本失效",
    transfer: "申请转交",
    transfer_confirmed: "确认停止并转交",
    ready: "设备就绪",
    not_ready: "设备暂不可用",
  };
  return `${who} · ${labels[event.kind] ?? event.kind}`;
}

export function TeamBranches({
  team,
  taskId,
  memberID,
  admin,
  members,
  devices,
  canManage = admin,
  onModeChange,
  viewMode = "all",
}: {
  team: string;
  taskId: number;
  memberID: number;
  admin: boolean;
  members: Member[];
  devices?: Device[];
  materials?: Artifact[];
  canManage?: boolean;
  onModeChange?: (enabled: boolean) => void;
  viewMode?: "all" | "review";
}) {
  const [snapshot, setSnapshot] = React.useState<Snapshot | null>(null);
  const data = snapshot?.project;
  const [enabled, setEnabled] = React.useState<boolean | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [poolForm, setPoolForm] = React.useState(false);
  const [policyForm, setPolicyForm] = React.useState(false);
  const [selectedBranch, setSelectedBranch] = React.useState(0);
  const [branchFilter, setBranchFilter] = React.useState<"mine" | "all">("mine");
  const [searchText, setSearchText] = React.useState("");
  const [appliedSearch, setAppliedSearch] = React.useState("");
  const [pollKey, setPollKey] = React.useState(0);
  const [pollError, setPollError] = React.useState("");
  const [actionError, setActionError] = React.useState("");
  const [notice, setNotice] = React.useState("");
  const [updated, setUpdated] = React.useState("");
  const [ownDevices, setOwnDevices] = React.useState<Device[]>(devices ?? []);
  const [newWorkKind, setNewWorkKind] = React.useState("pentest");
  const [newWorkMaterials, setNewWorkMaterials] = React.useState<string[]>([]);
  const scope = `${team}:${taskId}`;
  const scopeRef = React.useRef(scope);
  const snapshotRef = React.useRef<Snapshot | null>(null);
  const mutationVersion = React.useRef(0);
  const pendingIDs = React.useRef(new Map<string, string>());
  const lastSyncRef = React.useRef("");
  const base = branchPath(team, taskId);

  React.useEffect(() => {
    scopeRef.current = scope;
    setSnapshot(null);
    snapshotRef.current = null;
    setEnabled(null);
    setLoading(true);
    setPollError("");
    setActionError("");
    setNotice("");
    setSelectedBranch(0);
    setSearchText("");
    setAppliedSearch("");
    pendingIDs.current.clear();
    mutationVersion.current++;
  }, [scope]);

  React.useEffect(() => {
    if (enabled !== null) onModeChange?.(enabled);
  }, [enabled, onModeChange]);

  React.useEffect(() => {
    if (devices) {
      setOwnDevices(devices);
      return;
    }
    let active = true;
    http<WorkspaceDevices>(`/teams/${team}/workspace`)
      .then((value) => {
        if (active && scopeRef.current === scope) setOwnDevices(value.devices ?? []);
      })
      .catch(() => {
        if (active && scopeRef.current === scope) setOwnDevices([]);
      });
    return () => {
      active = false;
    };
  }, [devices, scope, team]);

  React.useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const load = async (full = false) => {
      const requestedScope = scope;
      const requestedMutation = mutationVersion.current;
      const after = !full && snapshotRef.current ? snapshotRef.current.cursor : 0;
      let nextDelay = 2000;
      try {
        const query = new URLSearchParams({ after: String(after), limit: "100" });
        if (appliedSearch) query.set("q", appliedSearch);
        const incoming = await http<Snapshot>(`${base}?${query.toString()}`);
        if (!active || scopeRef.current !== requestedScope || requestedMutation !== mutationVersion.current) return;
        const merged = mergeSnapshots(snapshotRef.current, incoming, !full);
        snapshotRef.current = merged;
        setSnapshot(merged);
        setEnabled(true);
        setPollError("");
        setUpdated(new Date().toLocaleTimeString());
        lastSyncRef.current = new Date().toLocaleTimeString();
        if (merged.has_more && merged.cursor > after) nextDelay = 0;
      } catch (error) {
        if (!active || scopeRef.current !== requestedScope || requestedMutation !== mutationVersion.current) return;
        const message = (error as Error).message;
        if (isPermissionDenied(error)) {
          mutationVersion.current++;
          snapshotRef.current = null;
          setSnapshot(null);
          setAppliedSearch("");
          setSearchText("");
          setPollError("你已无权查看此分支或任务协作内容，已清除本地缓存；系统将重新检查可见范围。");
          return;
        }
        if (!snapshotRef.current && isNotFound(error)) {
          setEnabled(false);
          setPollError("");
        } else {
          setPollError(`同步失败，保留上次状态：${message}`);
        }
      } finally {
        if (active && scopeRef.current === requestedScope) {
          setLoading(false);
          timer = setTimeout(() => void load(false), nextDelay);
        }
      }
    };
    setLoading(true);
    void load(true);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [appliedSearch, base, scope, pollKey]);

  React.useEffect(() => {
    if (data?.branches.length && !data.branches.some((branch) => branch.id === selectedBranch)) setSelectedBranch(data.branches[0].id);
  }, [data?.branches, selectedBranch]);

  const membersByID = React.useMemo(() => new Map(members.map((m) => [m.id, m])), [members]);
  const memberName = (id: number) => membersByID.get(id)?.login ?? `成员 ${id}`;
  const deviceName = (id: number) => ownDevices.find((d) => d.id === id)?.name ?? `设备 ${id}`;
  const permissions = new Set(snapshot?.permissions ?? []);
  const branchManage = admin || permissions.has("manage");
  const manage = branchManage;
  const canEnable = branchManage || canManage;
  const visibleBranches = (data?.branches ?? []).filter((branch) => viewMode === "review" ? ["review_pending", "needs_supplement"].includes(branch.state) : branchFilter === "all" || admin || branch.owner_id === memberID || branch.contributors.includes(memberID));
  const activeBranch = visibleBranches.find((branch) => branch.id === selectedBranch) ?? visibleBranches[0];
  const usableMembers = members.filter((m) => !m.revoked);
  const ownedDevices = ownDevices.filter((d) => !d.revoked && d.owner_member_id === memberID && (!d.capabilities || d.capabilities.execution_enabled !== false));

  async function refreshNow() {
    setLoading(true);
    const requested = scope;
    const requestedMutation = mutationVersion.current;
    try {
      let incoming: Snapshot | null = null;
      let cursor = 0;
      let pages = 0;
      do {
        const query = new URLSearchParams({ after: String(cursor), limit: "100" });
        if (appliedSearch) query.set("q", appliedSearch);
        const page = normalizeSnapshot(await http<Snapshot>(`${base}?${query.toString()}`));
        if (scopeRef.current !== requested || requestedMutation !== mutationVersion.current) return;
        incoming = mergeSnapshots(incoming, page, incoming !== null);
        pages++;
        if (page.has_more && page.cursor <= cursor) throw new Error("事件分页游标未前进，请重试刷新。");
        if (pages > 1000) throw new Error("事件分页超过安全上限，已停止刷新。");
        cursor = page.cursor;
        if (!page.has_more) break;
      } while (true);
      if (!incoming) return;
      const merged = mergeSnapshots(snapshotRef.current, incoming, false);
      snapshotRef.current = merged;
      setSnapshot(merged);
      setEnabled(true);
      setPollError("");
      setUpdated(new Date().toLocaleTimeString());
    } catch (error) {
      if (scopeRef.current === requested) {
        if (isPermissionDenied(error)) {
          mutationVersion.current++;
          snapshotRef.current = null;
          setSnapshot(null);
          setAppliedSearch("");
          setSearchText("");
          setPollError("你已无权查看此分支或任务协作内容，已清除本地缓存。");
        } else setPollError(`同步失败，保留上次状态：${(error as Error).message}`);
      }
    } finally {
      if (scopeRef.current === requested) setLoading(false);
    }
  }

  async function command(type: string, payload: Record<string, unknown>, success: string): Promise<boolean> {
    if (busy) return false;
    const draft = { type, ...payload };
    const signature = JSON.stringify(draft);
    const requestID = pendingIDs.current.get(signature) ?? newRequestID();
    pendingIDs.current.set(signature, requestID);
    const requestedScope = scope;
    const version = ++mutationVersion.current;
    setBusy(true);
    setActionError("");
    setNotice("");
    try {
      const response = await http<CommandResponse>(commandPath(team, taskId), {
        method: "POST",
        body: JSON.stringify({ ...draft, request_id: requestID }),
      });
      if (scopeRef.current !== requestedScope) return false;
      pendingIDs.current.delete(signature);
      if (response.snapshot) {
        // Command snapshots have no search filter and only one event page.
        // Refresh the visible query separately; never advance its cursor here.
        const replaceProjection = type === "grant";
        const merged = mergeSnapshots(replaceProjection ? null : snapshotRef.current, {
          ...response.snapshot, events: [],
          cursor: snapshotRef.current?.cursor ?? 0,
          has_more: snapshotRef.current?.has_more ?? false,
        }, !replaceProjection);
        snapshotRef.current = merged;
        setSnapshot(merged);
      }
      setNotice(success);
      setActionError("");
      mutationVersion.current = version + 1;
      setPollKey((value) => value + 1);
      return true;
    } catch (error) {
      if (scopeRef.current === requestedScope) {
        if (isPermissionDenied(error)) {
          mutationVersion.current = version + 1;
          snapshotRef.current = null;
          setSnapshot(null);
          setAppliedSearch("");
          setSearchText("");
          setActionError("权限已变化，此操作未获准；本地分支缓存已清除，请刷新后查看当前可用内容。");
        } else setActionError((error as Error).message);
      }
      return false;
    } finally {
      if (scopeRef.current === requestedScope) {
        setBusy(false);
        setLoading(false);
      }
    }
  }

  async function exportEvents() {
    try {
      let result: Snapshot | null = null;
      let cursor = 0;
      let pages = 0;
      do {
        const query = new URLSearchParams({ after: String(cursor), limit: "100" });
        if (activeBranch) query.set("branch", String(activeBranch.id));
        if (appliedSearch) query.set("q", appliedSearch);
        const page = normalizeSnapshot(await http<Snapshot>(`${base}/export?${query.toString()}`));
        result = mergeSnapshots(result, page, result !== null);
        pages++;
        if (page.has_more && page.cursor <= cursor) throw new Error("导出游标未前进，无法完整导出。");
        if (pages > 1000) throw new Error("导出记录超过安全分页上限。");
        cursor = page.cursor;
        if (!page.has_more) break;
      } while (true);
      if (!result) throw new Error("没有可导出的授权记录");
      const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `task-${taskId}-branches.json`;
      link.click();
      URL.revokeObjectURL(url);
      setActionError("");
    } catch (error) {
      setActionError(`导出失败：${(error as Error).message}`);
    }
  }

  if (!taskId) return null;

  return (
    <Card aria-labelledby={`branches-title-${taskId}`}>
      <CardHeader className="gap-2">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1">
            <CardTitle id={`branches-title-${taskId}`}>{viewMode === "review" ? "待人工复审" : "执行分支协作（可选）"}</CardTitle>
            <p className="max-w-3xl text-sm text-muted-foreground">
              在同一主任务下拆分独立工作上下文。每个分支保留自己的计划、执行记录和复核状态；分支复核不会自动结束主任务。
            </p>
          </div>
          <div className="flex items-center gap-2">
            {enabled && <Badge variant="outline">{stateNames[data?.state ?? ""] ?? data?.state ?? "已启用"}</Badge>}
            <Button type="button" variant="outline" size="sm" disabled={busy || loading} onClick={() => void refreshNow()}>
              刷新分支
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-5">
        {pollError && <p role="status" className="rounded-md border p-2 text-sm text-muted-foreground">{pollError}</p>}
        {actionError && <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">{actionError}</p>}
        {notice && <p role="status" className="text-sm">{notice}</p>}
        {loading && enabled === null && <p role="status" className="text-sm text-muted-foreground">正在检查分支协作状态…</p>}
        {enabled === false && viewMode === "all" && (
          <div className="space-y-3 rounded-md border p-4">
            <p className="text-sm text-muted-foreground">此共享任务尚未启用执行分支协作。启用需要管理员或任务管理权限，启用不会复制任务，也不会自动启动执行。</p>
            {canEnable ? (
              <TeamBranchSetup team={team} taskId={taskId} base={base} disabled={busy || loading} onEnabled={async () => {
                setEnabled(true);
                setNotice("协作配置已启用；主任务保持暂停，执行不会自动开始。请在协作工作台检查设备与分支状态后再决定是否启动。");
                mutationVersion.current++;
                await refreshNow();
              }} />
            ) : (
              <p className="text-sm">启用状态由任务管理者设置。</p>
            )}
          </div>
        )}

        {enabled === false && viewMode === "review" && <p className="rounded-md border p-3 text-sm text-muted-foreground">此任务尚未启用分支协作，因此没有待人工复审的分支。</p>}
        {enabled && data && snapshot && (
          <>
            {viewMode === "all" && <>
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-md bg-muted/40 p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-muted-foreground">任务 {taskId} · {data.policy.kinds.map(kindName).join("、")}</span>
                <Badge variant="secondary">总额度 {data.policy.budget}</Badge>
                <Badge variant="outline">单工具 ≤ {data.policy.max_tool_seconds} 秒</Badge>
                <Badge variant={data.state === "paused" ? "outline" : "secondary"}>{stateNames[data.state] ?? data.state}</Badge>
                <Badge variant={data.policy.auto_dispatch ? "secondary" : "outline"}>自动派发{data.policy.auto_dispatch ? "开启" : "关闭"}</Badge>
                <Badge variant={data.policy.auto_publish ? "secondary" : "outline"}>自动发布{data.policy.auto_publish ? "开启" : "关闭"}</Badge>
                <Badge variant={data.policy.auto_review === false ? "outline" : "secondary"}>{data.policy.auto_review === false ? "人工复核" : "明确结果自动接收"}</Badge>
                {[...permissions].map((permission) => <Badge key={permission} variant="outline">{permissionNames[permission] ?? permission}</Badge>)}
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span>2 秒同步 · 最近成功 {updated || lastSyncRef.current || "—"}</span>
                {loading && <span role="status">更新中</span>}
              </div>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border p-3">
              <p className="text-sm text-muted-foreground">{data.state === "paused" ? "项目当前保持暂停。" : "协作正在运行。"} {data.policy.auto_dispatch ? "开始后会自动拆分工作、匹配空闲设备并按授权范围分配资产。" : "自动派发已关闭，需由管理者在高级管理中发布工作单。"} {data.policy.auto_publish ? "候选工作可自动发布。" : "自动发布已关闭，候选工作需管理者批准。"} {data.policy.auto_review === false ? "候选结果由成员人工复核。" : "明确结果自动接收，不明确结果转人工复审；不会自动完成主任务。"}</p>
              {manage && <Button type="button" variant={data.state === "paused" ? "default" : "outline"} disabled={busy || data.state === "complete" || data.state === "partial"} onClick={() => void command(data.state === "paused" ? "project_resume" : "project_pause", { revision: data.revision }, data.state === "paused" ? (data.policy.auto_dispatch ? "协作已开始；系统将自动拆分、匹配空闲设备并分配授权资产。" : "协作已开始；自动派发关闭，请到高级管理手动发布工作单。") : "协作已暂停。")}>{data.state === "paused" ? "开始协作" : "暂停协作"}</Button>}
            </div>
            {(branchManage || manage) && <details className="rounded-md border p-3"><summary className="cursor-pointer font-medium">高级管理</summary><div className="mt-3 space-y-3">
            {branchManage && (
              <section className="space-y-3 rounded-md border p-4" aria-labelledby={`branch-permissions-heading-${taskId}`}>
                <div>
                  <h3 id={`branch-permissions-heading-${taskId}`} className="font-medium">成员分支权限</h3>
                  <p className="mt-1 text-xs text-muted-foreground">每项权限独立授予或撤销，不会连带增加其他权限。分支授权仍受主任务的查看与执行权限边界约束。</p>
                </div>
                <div className="space-y-3">
                  {members.map((member) => {
                    const granted = new Set(data.permissions?.[String(member.id)] ?? []);
                    return <fieldset key={member.id} className="space-y-2 rounded-md border p-3" disabled={busy || !!member.revoked}>
                      <legend className="px-1 text-sm font-medium">{member.login}{member.revoked ? "（已撤销成员）" : ""}</legend>
                      <div className="grid gap-2 sm:grid-cols-3 lg:grid-cols-5">
                        {branchPermissionKeys.map((permission) => {
                          const id = `branch-permission-${taskId}-${member.id}-${permission}`;
                          return <label key={permission} htmlFor={id} className="flex min-h-9 items-center gap-2 rounded-md border px-2 text-sm">
                            <input id={id} type="checkbox" checked={granted.has(permission)} disabled={busy || !!member.revoked} onChange={(event) => { const grant = event.currentTarget.checked; void command("grant", { member_id: member.id, permission, revoke: !grant }, `${member.login}：已${grant ? "授予" : "撤销"}${permissionNames[permission]}权限。`); }} />
                            {permissionNames[permission]}
                          </label>;
                        })}
                      </div>
                    </fieldset>;
                  })}
                </div>
              </section>
            )}
            {data.policy.auto_publish && <p className="text-xs text-muted-foreground">协调器自动发布已允许；这只发布候选工作单，不会跳过权限和设备就绪检查。</p>}
            {manage && (
              <section className="space-y-3 rounded-md border p-4" aria-labelledby={`branch-pool-heading-${taskId}`}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div><h3 id={`branch-pool-heading-${taskId}`} className="font-medium">工作池</h3><p className="text-xs text-muted-foreground">发布只创建候选工作项；成员领取后才建立分支上下文。</p></div>
                  <div className="flex gap-2">
                    <Button type="button" size="sm" variant="outline" disabled={busy || data.state === "complete" || data.state === "partial"} onClick={() => { const note = window.prompt("填写项目关闭说明或未完成缺口"); if (note?.trim()) void command("close", { revision: data.revision, state: "partial", text: note.trim() }, "项目关闭请求已记录；系统会按必需分支复核状态标记完成或部分完成。"); }}>关闭项目</Button>
                    <Button type="button" size="sm" variant="outline" aria-expanded={poolForm} onClick={() => setPoolForm((value) => !value)}>{poolForm ? "收起发布表单" : "发布工作单"}</Button>
                  </div>
                </div>
                {manage && <div className="border-t pt-3"><Button type="button" size="sm" variant="outline" aria-expanded={policyForm} onClick={() => setPolicyForm((value) => !value)}>{policyForm ? "收起范围与额度" : "增加资产或总额度"}</Button>{policyForm && <form className="mt-3 grid gap-3 md:grid-cols-[1fr_1fr_auto]" onSubmit={(event) => { event.preventDefault(); const form = event.currentTarget; const values = new FormData(form); let added: BranchAsset[]; try { added = parseAssets(String(values.get("assets") ?? "")); } catch (error) { setActionError((error as Error).message); return; } const budget = Number(values.get("budget")); if (!(budget > data.policy.budget)) { setActionError("新总额度必须大于当前总额度，已用额度会保留。"); return; } void command("extend_policy", { revision: data.revision, policy: { budget, assets: [...data.policy.assets, ...added] } }, "项目已暂停时可扩展的额度和资产范围已提交。").then((ok) => { if (ok) form.reset(); }); }}><div className="space-y-1"><Label htmlFor={`extend-assets-${taskId}`}>新增资产（每行 id=目标，可留空）</Label><Textarea id={`extend-assets-${taskId}`} name="assets" rows={2} placeholder="asset-3=https://authorized.example" disabled={busy} /></div><div className="space-y-1"><Label htmlFor={`extend-budget-${taskId}`}>新的总额度（请求与工具次数）</Label><Input id={`extend-budget-${taskId}`} name="budget" type="number" min={data.policy.budget + 1} defaultValue={data.policy.budget + 10} required disabled={busy} /></div><Button className="self-end" disabled={busy}>扩展范围</Button><p className="text-xs text-muted-foreground md:col-span-3">仅可在项目暂停且操作结束后增加；原资产版本和已用额度保持不变。</p></form>}</div>}
                {poolForm && (
                  <form className="space-y-3 border-t pt-3" onSubmit={(event) => {
                    event.preventDefault();
                    const form = event.currentTarget;
                    const values = new FormData(form);
                    const kind = String(values.get("kind") ?? "pentest");
                    const roleChoices = kind === "reverse" ? ["reverse_static", "reverse_reviewer"] : ["worker", "reviewer"];
                    const selectedMaterials = values.getAll("material_hashes").map(String);
                    const coordinator = values.get("coordinator") === "on";
                    void command("publish", { work: {
                      title: String(values.get("title") ?? "").trim(), question: String(values.get("question") ?? "").trim(), kind,
                      asset_ids: values.getAll("asset_ids").map(String), material_hashes: selectedMaterials, roles: roleChoices,
                      acceptance: String(values.get("acceptance") ?? "").split(/\r?\n/).map((x) => x.trim()).filter(Boolean),
                      budget: Number(values.get("budget")), resource_keys: String(values.get("resource_keys") ?? "").split(",").map((x) => x.trim()).filter(Boolean),
                      depends_on: values.getAll("depends_on").map(Number), restricted: values.get("restricted") === "on",
                      members: values.getAll("members").map(Number),
                      coordinator,
                    } }, coordinator ? "协调器工作已发布；成员仍需认领，设备就绪后由管理者恢复主项目。" : "工作单已发布到共享任务工作池。成员认领后才会建立分支上下文。").then(() => form.reset());
                  }}>
                    <div className="grid gap-3 md:grid-cols-2">
                      <div className="space-y-2"><Label htmlFor={`work-title-${taskId}`}>工作单标题</Label><Input id={`work-title-${taskId}`} name="title" required maxLength={300} disabled={busy} /></div>
                      <div className="space-y-2"><Label htmlFor={`work-kind-${taskId}`}>类型</Label><select id={`work-kind-${taskId}`} name="kind" className={controlClass} value={newWorkKind} onChange={(e) => { setNewWorkKind(e.target.value); setNewWorkMaterials([]); }} disabled={busy}>{data.policy.kinds.map((kind) => <option key={kind} value={kind}>{kindName(kind)}</option>)}</select></div>
                      <div className="space-y-2 md:col-span-2"><Label htmlFor={`work-question-${taskId}`}>要解决的问题</Label><Textarea id={`work-question-${taskId}`} name="question" required maxLength={8192} rows={2} disabled={busy} /></div>
                      <fieldset className="space-y-2"><legend className="text-sm font-medium">授权资产</legend><div className="flex flex-wrap gap-2">{data.policy.assets.map((asset) => <label key={asset.id} className="flex min-h-10 items-center gap-2 rounded-md border px-3 text-sm"><input type="checkbox" name="asset_ids" value={asset.id} disabled={busy} />{asset.id} <span className="text-muted-foreground">{asset.target}</span></label>)}</div></fieldset>
                      <fieldset className="space-y-2"><legend className="text-sm font-medium">可引用材料</legend><div className="flex flex-col gap-2">{data.policy.materials.map((material) => <label key={material.sha256} className="flex min-h-10 items-center gap-2 rounded-md border px-3 text-sm"><input type="checkbox" name="material_hashes" value={material.sha256} checked={newWorkMaterials.includes(material.sha256)} onChange={(e) => setNewWorkMaterials((current) => e.target.checked ? [...current, material.sha256] : current.filter((value) => value !== material.sha256))} disabled={busy} /><span className="truncate">{material.name}</span><span className="ml-auto text-xs text-muted-foreground">{material.sha256.slice(0, 12)}…</span></label>)}</div></fieldset>
                      <div className="space-y-2"><Label htmlFor={`work-budget-${taskId}`}>分支预算（请求与工具次数）</Label><Input id={`work-budget-${taskId}`} name="budget" type="number" min={1} max={data.policy.budget} defaultValue={10} required disabled={busy} /></div>
                      <div className="space-y-2"><Label htmlFor={`work-resources-${taskId}`}>共享互斥资源键（逗号分隔，可留空）</Label><Input id={`work-resources-${taskId}`} name="resource_keys" disabled={busy} /></div>
                      <fieldset className="space-y-2 rounded-md border p-3"><legend className="px-1 text-sm font-medium">协调器设置</legend><label className="flex min-h-9 items-center gap-2 text-sm"><input type="checkbox" name="coordinator" disabled={busy} />作为协调器工作</label><p className="text-xs text-muted-foreground">角色沿用当前类型配置：渗透使用 worker/reviewer，逆向使用 reverse_static/reverse_reviewer。规划器无工具能力，复核角色只读材料；执行能力沿用启用时配置的角色策略。</p></fieldset>
                      <div className="space-y-2"><Label htmlFor={`work-depends-${taskId}`}>依赖分支</Label><select id={`work-depends-${taskId}`} name="depends_on" multiple className={`${controlClass} min-h-24`} disabled={busy}>{data.branches.filter((branch) => branch.state !== "cancelled").map((branch) => <option key={branch.id} value={branch.id}>分支 #{branch.id} · {branch.spec.title} · {stateNames[branch.state] ?? branch.state}</option>)}</select></div>
                      <fieldset className="space-y-2"><legend className="text-sm font-medium">访问范围</legend><label className="flex min-h-10 items-center gap-2 text-sm"><input type="checkbox" name="restricted" disabled={busy} />受限分支</label><label className="text-xs text-muted-foreground">受限分支仅对指定成员、贡献者和管理员可见。</label>{usableMembers.map((member) => <label key={member.id} className="flex min-h-9 items-center gap-2 text-sm"><input type="checkbox" name="members" value={member.id} disabled={busy} />{member.login}</label>)}</fieldset>
                    </div>
                    <div className="flex flex-wrap gap-2"><Button disabled={busy}>{busy ? "正在发布…" : "发布到工作池"}</Button><Button type="button" variant="outline" disabled={busy} onClick={() => setPoolForm(false)}>取消</Button></div>
                  </form>
                )}
                <div className="space-y-2">
                  {(data.pool ?? []).length === 0 ? <p className="text-sm text-muted-foreground">工作池为空。发布一个工作单后，成员可以选择自己的设备领取。</p> : data.pool.map((work) => (
                    <article key={work.id} className="flex flex-wrap items-center justify-between gap-3 rounded-md border p-3">
                      <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="font-medium">{work.spec.title}</span><Badge variant="outline">{kindName(work.spec.kind)}</Badge>{work.spec.coordinator && <Badge variant="outline">协调器工作</Badge>}<Badge variant="secondary">{stateNames[work.state] ?? work.state}</Badge></div><p className="mt-1 text-sm text-muted-foreground">{work.spec.question}</p><p className="mt-1 text-xs text-muted-foreground">工作单 #{work.id} · 预算 {work.spec.budget}{work.branch_id ? ` · 分支 #${work.branch_id}` : ""}</p></div>
                      {work.state === "proposed" && <Button size="sm" disabled={busy || !manage} onClick={() => void command("approve", { work_id: work.id }, "工作单提议已批准。")}>批准提议</Button>}
                      {(work.state === "proposed" || work.state === "published") && <Button size="sm" variant="outline" disabled={busy} onClick={() => { const reason = window.prompt("取消未领取工作单的原因"); if (reason?.trim()) void command("cancel_work", { work_id: work.id, revision: data.revision, text: reason.trim() }, "未领取工作单已取消。"); }}>取消工作单</Button>}
                      {work.state === "published" && <form className="flex flex-wrap items-center gap-2" onSubmit={(event) => { event.preventDefault(); const form = event.currentTarget; const device = Number(new FormData(form).get("device_id")); void command("claim", { work_id: work.id, device_id: device }, "已领取分支；设备就绪前不会开始执行。"); }}><Label className="sr-only" htmlFor={`claim-device-${work.id}`}>选择自己的执行设备</Label><select id={`claim-device-${work.id}`} name="device_id" required className="min-h-10 max-w-56 rounded-md border bg-background px-3 text-sm" disabled={busy}><option value="">选择自己的设备</option>{ownedDevices.map((device) => <option key={device.id} value={device.id}>{device.name} · #{device.id}</option>)}</select><Button size="sm" disabled={busy || ownedDevices.length === 0}>领取分支</Button></form>}
                    </article>
                  ))}
                </div>
              </section>
            )}
            </div></details>}

            {!manage && (data.pool ?? []).length > 0 && <section className="space-y-2"><h3 className="font-medium">可领取工作</h3>{data.pool.filter((work) => work.state === "published").map((work) => <article key={work.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3"><div><p className="font-medium">{work.spec.title}</p><p className="text-sm text-muted-foreground">{work.spec.question} · 预算 {work.spec.budget}</p></div><form className="flex gap-2" onSubmit={(event) => { event.preventDefault(); const deviceID = Number(new FormData(event.currentTarget).get("device_id")); void command("claim", { work_id: work.id, device_id: deviceID }, "已领取分支；等待设备就绪。"); }}><Label className="sr-only" htmlFor={`claim-member-device-${work.id}`}>选择自己的设备</Label><select id={`claim-member-device-${work.id}`} name="device_id" required className="min-h-10 max-w-56 rounded-md border bg-background px-3 text-sm" disabled={busy}><option value="">选择自己的设备</option>{ownedDevices.map((device) => <option key={device.id} value={device.id}>{device.name} · #{device.id}</option>)}</select><Button size="sm" disabled={busy || ownedDevices.length === 0}>领取</Button></form></article>)}</section>}
            </>}

            <section className="space-y-3" aria-labelledby={`branch-list-heading-${taskId}`}>
              <div className="flex flex-wrap items-center justify-between gap-2"><div><h3 id={`branch-list-heading-${taskId}`} className="font-medium">{viewMode === "review" ? "待人工复审" : "执行分支"}</h3><p className="text-xs text-muted-foreground">{viewMode === "review" ? "仅显示待人工复审或需要补充的分支。" : `每个分支属于主任务 ${taskId}，拥有独立 epoch 与工作记录。`}</p></div>{viewMode === "all" && <div className="flex items-center gap-2"><Label htmlFor={`branch-filter-${taskId}`} className="sr-only">分支范围</Label><select id={`branch-filter-${taskId}`} value={branchFilter} className="min-h-10 rounded-md border bg-background px-3 text-sm" onChange={(e) => setBranchFilter(e.target.value as "mine" | "all")}><option value="mine">我的分支</option><option value="all">全部可见分支</option></select></div>}</div>
              {(data.branches ?? []).length === 0 ? <p className="rounded-md border p-4 text-sm text-muted-foreground">{viewMode === "review" ? "目前没有待人工复审的分支。" : "尚无已领取的执行分支。"}</p> : visibleBranches.length === 0 ? <p className="rounded-md border p-4 text-sm text-muted-foreground">{viewMode === "review" ? "目前没有待人工复审的分支。" : "当前筛选下没有可见分支。"}</p> : <div className="grid gap-3 lg:grid-cols-[minmax(16rem,0.8fr)_minmax(0,1.5fr)]">
                <div className="space-y-2">
                  {visibleBranches.map((branch) => <button key={branch.id} type="button" aria-pressed={activeBranch?.id === branch.id} onClick={() => setSelectedBranch(branch.id)} className={`w-full rounded-md border p-3 text-left transition-colors hover:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${activeBranch?.id === branch.id ? "border-primary bg-muted/50" : ""}`}>
                    <div className="flex flex-wrap items-center gap-2"><span className="font-medium">{branch.spec.title}</span><Badge variant="outline">{branchStateName(branch)}</Badge>{branch.review_mode === "automatic" && <Badge variant="secondary">自动核验</Badge>}{branch.spec.restricted && <Badge variant="secondary">受限可见</Badge>}</div>
                    {branch.review_reason && <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">核验说明：{branch.review_reason}</p>}
                    <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">{branch.spec.question}</p>
                    <p className="mt-2 text-xs text-muted-foreground">主任务 #{branch.task_id} · 成员 {memberName(branch.owner_id)} · {deviceName(branch.device_id)} #{branch.device_id}</p>
                    <p className="mt-1 text-xs text-muted-foreground">额度 {branch.spent}/{branch.spec.budget} · epoch {branch.epoch} · 修订 {branch.revision}</p>
                    {branch.reason && <p className="mt-2 text-xs text-amber-700 dark:text-amber-300">{branch.reason}</p>}
                  </button>)}
                </div>

                {activeBranch && <BranchDetail
                  branch={activeBranch} events={snapshot.events.filter((event) => event.branch_id === activeBranch.id)}
                  members={usableMembers} memberID={memberID} admin={admin} permissions={permissions} devices={ownDevices}
                  policy={data.policy} team={team} taskId={taskId} busy={busy} memberName={memberName} deviceName={deviceName} onCommand={command} onExport={exportEvents}
                  searchText={searchText} onSearchText={setSearchText} onSearch={() => { setAppliedSearch(searchText.trim()); setSnapshot((current) => { if (!current) return current; const next = { ...current, events: [] }; snapshotRef.current = next; return next; }); mutationVersion.current++; setPollKey((value) => value + 1); }}
                  taskState={data.state}
                />}
              </div>}
            </section>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function BranchDetail({
  team, taskId, branch, events, members, memberID, admin, permissions, devices, policy, busy, memberName, deviceName, onCommand, onExport,
  searchText, onSearchText, onSearch, taskState,
}: {
  team: string; taskId: number; branch: Branch; events: BranchEvent[]; members: Member[]; memberID: number; admin: boolean;
  permissions: Set<string>; devices: Device[]; policy: BranchPolicy; busy: boolean; memberName: (id: number) => string; deviceName: (id: number) => string;
  onCommand: (type: string, payload: Record<string, unknown>, success: string) => Promise<boolean>; onExport: () => Promise<void>;
  searchText: string; onSearchText: (value: string) => void; onSearch: () => void; taskState: string;
}) {
  const [transferMember, setTransferMember] = React.useState("");
  const [transferDevice, setTransferDevice] = React.useState("");
  const [reviewNote, setReviewNote] = React.useState("");
  const [guideText, setGuideText] = React.useState("");
  const [discussionText, setDiscussionText] = React.useState("");
  const [downloadError, setDownloadError] = React.useState("");
  const [activeTab, setActiveTab] = React.useState<"events" | "units">("events");
  const controlAllowed = admin || (permissions.has("control") && branch.control_id === memberID);
  const guideAllowed = admin || (permissions.has("guide") && branch.control_id === memberID);
  const discussAllowed = admin || permissions.has("discuss");
  const evidenceAllowed = admin || permissions.has("evidence");
  const processAllowed = admin || permissions.has("process");
  const reviewAllowed = permissions.has("review") && memberID > 0 && !branch.contributors.includes(memberID) && branch.state === "review_pending";
  const targetMember = Number(transferMember);
  const transferDevices = devices.filter((device) => !device.revoked && device.owner_member_id === targetMember);
  React.useEffect(() => { setTransferDevice(""); }, [transferMember]);

  async function submitText(type: "discuss" | "guide", value: string, clear: (s: string) => void) {
    const text = value.trim();
    if (!text) return;
    const saved = await onCommand(type, { branch_id: branch.id, text }, type === "guide" ? "指导已排队，设备会在下一次同步时收到。" : "讨论已记录；讨论不会进入执行指令。");
    if (saved) clear("");
  }

  async function downloadSmallMaterial(material: Material) {
    setDownloadError("");
    try {
      const token = localStorage.getItem("artex_token");
      const chunks: BlobPart[] = [];
      const step = 4 * 1024 * 1024;
      const urlPath = `/api${branchPath(team, taskId)}/${branch.id}/materials/${encodeURIComponent(material.sha256)}`;
      for (let start = 0; start < material.size || (material.size === 0 && start === 0); start += step) {
        const end = Math.min(material.size - 1, start + step - 1);
        const headers = new Headers(token ? { Authorization: `Bearer ${token}` } : {});
        if (material.size > step) headers.set("Range", `bytes=${start}-${end}`);
        const response = await fetch(urlPath, { headers, cache: "no-store" });
        if (response.status !== (material.size > step ? 206 : 200)) throw new Error(`下载请求失败：HTTP ${response.status}`);
        if (material.size > step && response.headers.get("Content-Range") !== `bytes ${start}-${end}/${material.size}`) throw new Error("分段范围与材料长度不符，已停止下载。");
        const chunk = await response.blob();
        if (chunk.size !== end - start + 1) throw new Error("材料分段长度不符，已停止下载。");
        chunks.push(chunk);
        if (material.size === 0) break;
      }
      const blob = new Blob(chunks, { type: "application/octet-stream" });
      if (blob.size !== material.size) throw new Error("下载内容长度与登记材料不符。");
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", await blob.arrayBuffer()));
      const sha256 = [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
      if (sha256.toLowerCase() !== material.sha256.toLowerCase()) throw new Error("SHA-256 校验失败，文件未保存。");
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = material.name || `${material.sha256}.bin`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      setDownloadError((error as Error).message);
    }
  }

  return <article className="min-w-0 space-y-4 rounded-md border p-4" aria-labelledby={`branch-detail-title-${branch.id}`}>
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><h4 id={`branch-detail-title-${branch.id}`} className="font-semibold">分支 #{branch.id} · {branch.spec.title}</h4><Badge variant="outline">{branchStateName(branch)}</Badge>{branch.review_mode === "automatic" && <Badge variant="secondary">自动核验</Badge>}</div><p className="mt-1 text-sm text-muted-foreground">{branch.spec.question}</p><p className="mt-2 text-xs text-muted-foreground">负责人 {memberName(branch.owner_id)} · 控制者 {memberName(branch.control_id)} · 设备 #{branch.device_id} {deviceName(branch.device_id)} · epoch {branch.epoch}</p>{branch.review_reason && <p className="mt-2 rounded-md bg-muted/50 p-2 text-xs">核验说明：{branch.review_reason}</p>}{branch.spec.restricted && <p className="mt-1 text-xs text-muted-foreground">受限分支仅对指定成员、贡献者和管理员可见。</p>}{branch.reason && <p className="mt-2 rounded-md bg-muted p-2 text-sm">阻塞说明：{branch.reason}</p>}</div>
    </div>
    <div className="flex flex-wrap gap-2 text-xs"><Badge variant="secondary">已用 {branch.spent}/{branch.spec.budget}</Badge><Badge variant="outline">{branch.spec.kind === "reverse" ? "逆向" : "渗透"}</Badge><Badge variant="outline">工作单 {branch.units.length}</Badge><Badge variant="outline">成员 {branch.contributors.map(memberName).join("、") || memberName(branch.owner_id)}</Badge></div>

    {controlAllowed && branch.state !== "accepted" && branch.state !== "cancelled" && (
      <div className="flex flex-wrap gap-2 border-y py-3">
        {branch.state === "running" && <Button type="button" variant="outline" disabled={busy} onClick={() => void onCommand("pause", { branch_id: branch.id, revision: branch.revision }, "分支将在当前工具操作结束后暂停。")}>暂停分支</Button>}
        {(branch.state === "paused" || branch.state === "needs_supplement") && <Button type="button" variant="outline" disabled={busy || taskState === "paused"} onClick={() => void onCommand("resume", { branch_id: branch.id, revision: branch.revision }, "原分支已恢复，预算不会重置。")}>恢复原分支</Button>}
        <Button type="button" variant="outline" disabled={busy} onClick={() => { if (!window.confirm("立即停止此分支？正在执行的操作会取消；不撤销已提交的证据。")) return; void onCommand("stop", { branch_id: branch.id, revision: branch.revision }, "分支已停止。"); }}>立即停止</Button>
        <Button type="button" variant="outline" disabled={busy} onClick={() => void onCommand("control_takeover", { branch_id: branch.id, member_id: memberID, revision: branch.revision }, "控制权已切换到当前成员。")}>接管控制</Button>
      </div>
    )}

    {controlAllowed && branch.state !== "accepted" && branch.state !== "cancelled" && (
      <form className="grid gap-2 rounded-md bg-muted/30 p-3 sm:grid-cols-[1fr_1fr_auto]" onSubmit={(event) => { event.preventDefault(); const form = event.currentTarget; const value = new FormData(form); const member = Number(value.get("member_id")); const device = Number(value.get("device_id")); const text = String(value.get("note") ?? "").trim(); if (!text) return; void onCommand("transfer", { branch_id: branch.id, member_id: member, device_id: device, text, revision: branch.revision }, "已登记安全交接；新负责人要等旧设备确认停止或租约结束后才能接手。").then((ok) => { if (ok) form.reset(); }); }}>
        <div className="space-y-1"><Label htmlFor={`transfer-member-${branch.id}`}>转交给成员</Label><select id={`transfer-member-${branch.id}`} name="member_id" required value={transferMember} onChange={(e) => setTransferMember(e.target.value)} className={controlClass} disabled={busy}><option value="">选择负责人</option>{members.map((member) => <option key={member.id} value={member.id}>{member.login}</option>)}</select></div>
        <div className="space-y-1"><Label htmlFor={`transfer-device-${branch.id}`}>该成员自己的设备</Label><select id={`transfer-device-${branch.id}`} name="device_id" required value={transferDevice} onChange={(e) => setTransferDevice(e.target.value)} className={controlClass} disabled={busy || !transferMember}><option value="">选择设备</option>{transferDevices.map((device) => <option key={device.id} value={device.id}>{device.name} · #{device.id}</option>)}</select></div>
        <div className="space-y-1 sm:col-span-3"><Label htmlFor={`transfer-note-${branch.id}`}>交接原因</Label><Input id={`transfer-note-${branch.id}`} name="note" required maxLength={2000} disabled={busy} /></div>
        <Button className="sm:col-span-3 sm:justify-self-start" disabled={busy || !transferMember || !transferDevice}>请求安全交接</Button>
      </form>
    )}

    {controlAllowed && branch.state === "transfer_wait" && (
      <form className="space-y-2 rounded-md border p-3" onSubmit={(event) => { event.preventDefault(); const note = String(new FormData(event.currentTarget).get("note") ?? "").trim(); if (note) void onCommand("confirm_stopped", { branch_id: branch.id, text: note, revision: branch.revision }, "已确认停止；分支 epoch 已更新并等待新设备就绪。"); }}>
        <Label htmlFor={`confirm-stop-${branch.id}`}>确认旧设备已停止并说明依据</Label>
        <Input id={`confirm-stop-${branch.id}`} name="note" required maxLength={2000} disabled={busy} />
        <Button variant="outline" disabled={busy}>确认停止并完成交接</Button>
      </form>
    )}

    {reviewAllowed && (
      <form className="space-y-2 rounded-md border p-3" onSubmit={(event) => { event.preventDefault(); const decision = String(new FormData(event.currentTarget).get("decision")); const note = reviewNote.trim(); if (note) void onCommand("review", { branch_id: branch.id, state: decision, text: note }, decision === "accept" ? "独立复核已通过；主任务仍需原流程验收。" : "已退回原分支补充，预算不会重置。").then(() => setReviewNote("")); }}>
        <h5 className="font-medium">独立复核</h5><p className="text-xs text-muted-foreground">提交人和贡献者不能复核自己的分支。</p>
        <Label htmlFor={`review-note-${branch.id}`}>复核依据与限制</Label><Textarea id={`review-note-${branch.id}`} value={reviewNote} onChange={(e) => setReviewNote(e.target.value)} required maxLength={8000} rows={3} disabled={busy} />
        <div className="flex flex-wrap items-center gap-2"><Label htmlFor={`review-decision-${branch.id}`} className="sr-only">复核结论</Label><select id={`review-decision-${branch.id}`} name="decision" className="min-h-10 rounded-md border bg-background px-3 text-sm" disabled={busy}><option value="accept">通过独立复核</option><option value="supplement">退回原分支补充</option></select><Button disabled={busy}>提交复核</Button></div>
      </form>
    )}

    {(discussAllowed || guideAllowed) && <div className="grid gap-3 md:grid-cols-2">
      {discussAllowed && <form className="space-y-2 rounded-md border p-3" onSubmit={(event) => { event.preventDefault(); void submitText("discuss", discussionText, setDiscussionText); }}><h5 className="font-medium">讨论</h5><p className="text-xs text-muted-foreground">讨论只记录为消息，不会作为执行指令发送给设备。</p><Label htmlFor={`discussion-${branch.id}`}>讨论内容</Label><Textarea id={`discussion-${branch.id}`} value={discussionText} onChange={(e) => setDiscussionText(e.target.value)} maxLength={4096} rows={2} disabled={busy} /><Button variant="outline" disabled={busy || !discussionText.trim()}>发送讨论</Button></form>}
      {guideAllowed && <form className="space-y-2 rounded-md border p-3" onSubmit={(event) => { event.preventDefault(); void submitText("guide", guideText, setGuideText); }}><h5 className="font-medium">指导</h5><p className="text-xs text-muted-foreground">仅分支控制者或管理员可排队指导；设备会回报收到与应用状态。</p><Label htmlFor={`guidance-${branch.id}`}>指导内容</Label><Textarea id={`guidance-${branch.id}`} value={guideText} onChange={(e) => setGuideText(e.target.value)} maxLength={4096} rows={2} disabled={busy} /><Button disabled={busy || !guideText.trim()}>发送指导</Button>{branch.guidance && branch.guidance.length > 0 && <ul className="space-y-1 text-xs text-muted-foreground">{branch.guidance.map((item) => <li key={item.id}>指导 #{item.id} · {item.status} · {item.text}</li>)}</ul>}</form>}
    </div>}

    {branch.guidance && branch.guidance.length > 0 && !guideAllowed && <div className="space-y-1 rounded-md border p-3"><h5 className="font-medium text-sm">指导状态</h5>{branch.guidance.map((item) => <p key={item.id} className="text-xs text-muted-foreground">#{item.id} · {item.status} · {item.text}</p>)}</div>}

    {branch.spec.material_hashes.length > 0 && <section className="space-y-2 rounded-md border p-3" aria-label="分支授权材料"><h5 className="font-medium text-sm">授权材料版本</h5>{policy.materials.filter((material) => branch.spec.material_hashes.includes(material.sha256)).map((material) => <div key={material.sha256} className="flex flex-wrap items-center justify-between gap-2 text-xs"><span>{material.name} · {material.size.toLocaleString()} B</span><code className="break-all text-muted-foreground">SHA-256 {material.sha256}</code>{evidenceAllowed && <Button type="button" size="sm" variant="outline" onClick={() => void downloadSmallMaterial(material)}>{material.size > 4 * 1024 * 1024 ? "分段校验下载" : "校验并下载"}</Button>}</div>)}<p className="text-xs text-muted-foreground">大于 4 MiB 时分段下载；保存前会校验登记长度和 SHA-256。</p>{downloadError && <p role="alert" className="text-xs text-destructive">{downloadError}</p>}</section>}

    <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-2">
      <div role="tablist" aria-label="分支详情视图" className="flex gap-1 rounded-md bg-muted p-1">
        <button type="button" role="tab" aria-selected={activeTab === "events"} className={`min-h-10 rounded px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${activeTab === "events" ? "bg-background" : "text-muted-foreground"}`} onClick={() => setActiveTab("events")}>过程与证据</button>
        <button type="button" role="tab" aria-selected={activeTab === "units"} className={`min-h-10 rounded px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${activeTab === "units" ? "bg-background" : "text-muted-foreground"}`} onClick={() => setActiveTab("units")}>工作单</button>
      </div>
      <div className="flex flex-wrap gap-2">
        {processAllowed && activeTab === "events" && <form className="flex gap-2" onSubmit={(event) => { event.preventDefault(); onSearch(); }}><Label htmlFor={`branch-search-${branch.id}`} className="sr-only">搜索分支过程和证据</Label><Input id={`branch-search-${branch.id}`} value={searchText} onChange={(e) => onSearchText(e.target.value)} maxLength={200} placeholder="搜索过程与证据" className="min-h-10 w-48" /><Button size="sm" variant="outline">搜索</Button></form>}
        {processAllowed && <Button type="button" size="sm" variant="outline" onClick={() => void onExport()}>导出授权过程</Button>}
      </div>
    </div>

    {activeTab === "events" && (
      !processAllowed ? <p className="text-sm text-muted-foreground">当前权限不包含过程查看。你仍可使用被单独授权的证据读取功能。</p> :
      events.length === 0 ? <p className="rounded-md border p-4 text-sm text-muted-foreground">没有符合当前筛选条件的过程记录。</p> :
      <ol className="max-h-[32rem] space-y-2 overflow-y-auto pr-1" aria-label={`分支 ${branch.id} 执行过程`}>
        {events.map((event) => <li key={event.id} className="rounded-md border p-3">
          <div className="flex flex-wrap items-start justify-between gap-2"><div><p className="font-medium text-sm">{eventTitle(event, memberName, deviceName)}</p><p className="mt-1 whitespace-pre-wrap break-words text-sm">{event.text}</p></div><time className="text-xs text-muted-foreground" dateTime={event.created_at}>{new Date(event.created_at).toLocaleString()}</time></div>
          {event.unit_id && <p className="mt-1 text-xs text-muted-foreground">工作单 #{event.unit_id} · epoch {event.epoch}</p>}
          {event.evidence && evidenceAllowed && <details className="mt-2 rounded-md bg-muted p-2"><summary className="cursor-pointer py-1 text-sm">证据 · {event.evidence.tool} · SHA-256 {event.evidence.sha256.slice(0, 16)}…</summary><pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">{event.evidence.content}</pre></details>}
        </li>)}
      </ol>
    )}
    {activeTab === "units" && <div className="space-y-2">{branch.units.length === 0 ? <p className="rounded-md border p-4 text-sm text-muted-foreground">设备就绪后会在这里记录分支内工作单。</p> : branch.units.map((unit) => <article key={unit.id} className="rounded-md border p-3"><div className="flex flex-wrap items-center gap-2"><span className="font-medium">{unit.spec.key}</span><Badge variant="outline">{unit.spec.role}</Badge><Badge variant="secondary">{unit.state}</Badge>{unit.attempt > 0 && <span className="text-xs text-muted-foreground">尝试 {unit.attempt}</span>}</div><p className="mt-2 whitespace-pre-wrap text-sm">{unit.spec.question}</p>{unit.result && evidenceAllowed && <div className="mt-3 space-y-2 rounded-md bg-muted/50 p-3"><p className="text-sm">{unit.result.outcome} · {unit.result.summary}</p>{unit.evidence_version && <p className="break-all text-xs text-muted-foreground">证据版本 {unit.evidence_version}</p>}{unit.result.evidence?.map((item) => <details key={item.sha256} className="rounded-md border bg-background p-2"><summary className="cursor-pointer text-sm">{item.tool} · SHA-256 {item.sha256.slice(0, 16)}…</summary><pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">{item.content}</pre></details>)}</div>}</article>)}</div>}
    {activeTab === "units" && (admin || permissions.has("manage")) && branch.units.filter((unit) => unit.spec.role === "reverse_dynamic" && unit.state === "planned" && !unit.spec.runtime).map((unit) => <form key={unit.id} className="grid gap-2 rounded-md border p-3 sm:grid-cols-[1fr_auto]" onSubmit={(event) => { event.preventDefault(); const profileID = String(new FormData(event.currentTarget).get("profile") ?? ""); const profile = devices.find((device) => device.id === branch.device_id)?.capabilities?.runtime_profiles?.find((item) => item.id === profileID); if (!profile) return; void onCommand("authorize_runtime", { branch_id: branch.id, unit_id: unit.id, device_id: branch.device_id, revision: branch.revision, runtime: { ...profile, artifact_hashes: unit.spec.material_hashes ?? [] } }, "动态环境仅获准用于此工作单。"); }}><div className="space-y-1"><Label htmlFor={"runtime-profile-" + branch.id + "-" + unit.id}>为此工作单授权动态环境</Label><select id={"runtime-profile-" + branch.id + "-" + unit.id} name="profile" required className={controlClass} disabled={busy}><option value="">选择设备已公布的环境</option>{devices.find((device) => device.id === branch.device_id)?.capabilities?.runtime_profiles?.map((profile) => <option key={profile.id} value={profile.id}>{profile.name} · {profile.platform}</option>)}</select><p className="text-xs text-muted-foreground">授权只绑定当前分支工作单和已列出的材料哈希。</p></div><Button className="self-end" variant="outline" disabled={busy}>仅授权给此工作单</Button></form>)}
  </article>;
}
