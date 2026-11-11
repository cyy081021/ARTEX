"use client";

import * as React from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { http } from "@/lib/api";

type Options = {
  budget: number;
  max_tool_seconds: number;
  min_tool_interval_ms: number;
  auto_dispatch: boolean;
  auto_publish: boolean;
  auto_review: boolean;
  include_other_kind: boolean;
  include_dynamic: boolean;
};
type Role = { key: string; capabilities: string[]; issues: string[]; ready: boolean };
type Device = { id: number; name: string; member_id: number; member_name: string; online: boolean; matched: boolean; roles: Role[]; issues: string[] };
type Plan = {
  token: string;
  expires_at: string;
  task: { id: number; name: string; kind: string; goal: string };
  assets: { id: string; target: string; version: string }[];
  constraints: { kind: string; text: string; origin: string }[];
  materials: { id: string; name: string; size_bytes: number; sha256: string }[];
  devices: Device[];
  options: Options;
  blockers: string[];
  warnings: string[];
  can_enable: boolean;
};

const defaults: Options = { budget: 100, max_tool_seconds: 60, min_tool_interval_ms: 0, auto_dispatch: true, auto_publish: true, auto_review: true, include_other_kind: false, include_dynamic: false };
const kindLabel = (kind: string) => kind === "reverse" ? "逆向" : kind === "pentest" ? "渗透" : kind;
const roleLabel: Record<string, string> = { planner: "渗透规划", worker: "渗透执行", reviewer: "渗透复核", reverse_planner: "逆向规划", reverse_static: "逆向静态分析", reverse_reviewer: "逆向复核", reverse_dynamic: "逆向动态观察" };
const issueLabel: Record<string, string> = {
  model_unavailable: "此设备没有可用的模型配置",
  planner_has_tools: "规划角色应保持无工具能力",
  tool_unconfigured: "所需工具尚未配置",
  mcp_server_unconfigured: "所需工具服务尚未配置",
  scope_fields_missing: "工具缺少必要的目标范围限制字段",
  read_only_required: "复核角色需要配置为只读",
  runtime_profile_unavailable: "没有可用的动态运行环境",
  role_unconfigured: "此角色尚未配置",
};
const explainIssue = (issue: string) => issueLabel[issue] ?? (/^[a-z0-9_]+$/.test(issue) ? "本地能力检查尚未通过" : issue);

export function TeamBranchSetup({ team, taskId, base, disabled, onEnabled }: { team: string; taskId: number; base: string; disabled?: boolean; onEnabled: () => Promise<void> | void }) {
  const [options, setOptions] = React.useState<Options>(defaults);
  const [advanced, setAdvanced] = React.useState(false);
  const [plan, setPlan] = React.useState<Plan | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [checked, setChecked] = React.useState(false);
  const [error, setError] = React.useState("");
  const scope = `${team}:${taskId}`;
  const currentScope = React.useRef(scope);
  const generation = React.useRef(0);

  React.useEffect(() => {
    currentScope.current = scope;
    generation.current++;
    setPlan(null);
    setChecked(false);
    setError("");
    setOptions(defaults);
  }, [scope]);

  function changeOptions(next: Options) {
    setOptions(next);
    setPlan(null);
    setChecked(false);
    setError("");
  }

  async function preview(event: React.FormEvent) {
    event.preventDefault();
    if (busy || disabled) return;
    if (!Number.isInteger(options.budget) || options.budget < 1 || options.budget > 100000 || !Number.isInteger(options.max_tool_seconds) || options.max_tool_seconds < 1 || options.max_tool_seconds > 60 || !Number.isInteger(options.min_tool_interval_ms) || options.min_tool_interval_ms < 0 || options.min_tool_interval_ms > 60000) {
      setError("请检查额度、工具时限和调用间隔范围。");
      return;
    }
    const requested = scope;
    const version = ++generation.current;
    setPlan(null);
    setChecked(false);
    setBusy(true);
    setError("");
    try {
      const result = await http<Plan>(`${base}/setup`, { method: "POST", body: JSON.stringify(options) });
      if (currentScope.current !== requested || generation.current !== version) return;
      setPlan(result);
      setOptions(result.options);
      setChecked(false);
      if (!result.can_enable) setError("预览发现阻断项，修复后请重新生成方案。");
    } catch (e) {
      if (currentScope.current === requested && generation.current === version) setError(`生成预览失败：${(e as Error).message}。请刷新方案后重试。`);
    } finally {
      if (currentScope.current === requested && generation.current === version) setBusy(false);
    }
  }

  async function enable() {
    if (busy || disabled || !plan || !plan.can_enable || !checked) return;
    const requested = scope;
    const version = generation.current;
    setBusy(true);
    setError("");
    try {
      await http(`${base}/enable`, { method: "POST", body: JSON.stringify({ setup_token: plan.token, setup_options: plan.options, confirm: true }) });
      if (currentScope.current !== requested || generation.current !== version) return;
      setPlan(null);
      await onEnabled();
    } catch (e) {
      if (currentScope.current === requested) {
        generation.current++;
        setPlan(null);
        setChecked(false);
        setError(`启用未完成：${(e as Error).message}。预览已作废，请刷新方案后重新核对。`);
      }
    } finally {
      if (currentScope.current === requested) setBusy(false);
    }
  }

  return <div className="space-y-4">
    <form className="space-y-3" onSubmit={(event) => void preview(event)}>
      <div className="flex flex-wrap items-center gap-2"><Button disabled={busy || disabled}>{busy ? "正在处理…" : plan ? "刷新自动方案" : "自动生成协作方案"}</Button><span className="text-xs text-muted-foreground">从主任务授权范围和已登记材料生成预览，并匹配团队设备能力。</span></div>
      <details className="rounded-md border p-3" open={advanced} onToggle={(event) => setAdvanced(event.currentTarget.open)}>
        <summary className="cursor-pointer text-sm font-medium">高级设置</summary>
        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          <div className="space-y-1"><Label htmlFor={`setup-budget-${taskId}`}>总额度（1–100000）</Label><Input id={`setup-budget-${taskId}`} type="number" min={1} max={100000} value={options.budget} disabled={busy || disabled} onChange={(e) => changeOptions({ ...options, budget: Number(e.target.value) })} /></div>
          <div className="space-y-1"><Label htmlFor={`setup-seconds-${taskId}`}>单工具时限（1–60 秒）</Label><Input id={`setup-seconds-${taskId}`} type="number" min={1} max={60} value={options.max_tool_seconds} disabled={busy || disabled} onChange={(e) => changeOptions({ ...options, max_tool_seconds: Number(e.target.value) })} /></div>
          <div className="space-y-1"><Label htmlFor={`setup-interval-${taskId}`}>最小调用间隔（0–60000 毫秒）</Label><Input id={`setup-interval-${taskId}`} type="number" min={0} max={60000} value={options.min_tool_interval_ms} disabled={busy || disabled} onChange={(e) => changeOptions({ ...options, min_tool_interval_ms: Number(e.target.value) })} /></div>
          <label className="flex min-h-9 items-center gap-2 text-sm"><input type="checkbox" checked={options.include_other_kind} disabled={busy || disabled} onChange={(e) => changeOptions({ ...options, include_other_kind: e.target.checked })} />包含另一种工作流程</label>
          <label className="flex min-h-9 items-center gap-2 text-sm"><input type="checkbox" checked={options.include_dynamic} disabled={busy || disabled} onChange={(e) => changeOptions({ ...options, include_dynamic: e.target.checked })} />包含逆向动态观察角色</label>
          <label className="flex min-h-9 items-center gap-2 text-sm"><input type="checkbox" checked={options.auto_dispatch} disabled={busy || disabled} onChange={(e) => changeOptions({ ...options, auto_dispatch: e.target.checked })} />开始协作后自动拆分和派发</label>
          <label className="flex min-h-9 items-center gap-2 text-sm"><input type="checkbox" checked={options.auto_publish} disabled={busy || disabled} onChange={(e) => changeOptions({ ...options, auto_publish: e.target.checked })} />允许协调器自动发布候选工作单（关闭后须管理者批准）</label>
          <label className="flex min-h-9 items-center gap-2 text-sm"><input type="checkbox" checked={options.auto_review} disabled={busy || disabled} onChange={(e) => changeOptions({ ...options, auto_review: e.target.checked })} />明确结果自动接收，不明确转人工复审</label>
        </div>
      </details>
    </form>

    {error && <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">{error}</p>}
    {plan && <section className="space-y-4 rounded-md border p-4" aria-label="协作方案预览">
      <div><h3 className="font-medium">启用前请核对方案</h3><p className="text-xs text-muted-foreground">方案有效期至 {new Date(plan.expires_at).toLocaleString()}。更改选项、切换任务或刷新页面后需要重新生成。</p></div>
      <div className="rounded-md bg-muted/40 p-3 text-sm"><p className="font-medium">主任务 #{plan.task.id} · {plan.task.name || "未命名"} · {kindLabel(plan.task.kind)}</p><p className="mt-1 whitespace-pre-wrap">{plan.task.goal}</p><p className="mt-2 text-xs text-muted-foreground">额度 {plan.options.budget} · 工具时限 {plan.options.max_tool_seconds} 秒 · 最小间隔 {plan.options.min_tool_interval_ms} 毫秒 · 自动派发{plan.options.auto_dispatch ? "开启" : "关闭"} · 候选工作自动发布{plan.options.auto_publish ? "开启" : "关闭"}{plan.options.auto_publish ? "" : "（需管理者批准后发布）"}</p><p className="text-xs text-muted-foreground">包含流程：{kindLabel(plan.task.kind)}{plan.options.include_other_kind ? `、${plan.task.kind === "reverse" ? "渗透" : "逆向"}` : ""}{plan.options.include_dynamic ? " · 含逆向动态观察" : ""}</p><p className="text-xs text-muted-foreground">核验策略：{plan.options.auto_review ? "明确结果自动接收，不明确结果转人工复审；主任务仍需原流程验收" : "由成员人工复审，主任务仍需原流程验收"}</p></div>
      <div><h4 className="text-sm font-medium">授权资产（{plan.assets.length}）</h4>{plan.assets.length ? <ul className="mt-1 space-y-1 text-sm">{plan.assets.map((a) => <li key={a.id} className="break-all">{a.target} <span className="text-xs text-muted-foreground">· 编号 {a.id}</span><details className="ml-4 text-xs text-muted-foreground"><summary className="cursor-pointer py-1">查看资产版本</summary><p className="break-all">{a.version}</p></details></li>)}</ul> : <p className="mt-1 text-sm text-muted-foreground">没有可自动纳入的主任务授权资产。</p>}</div>
      <div><h4 className="text-sm font-medium">任务约束（{plan.constraints.length}）</h4>{plan.constraints.length ? <ul className="mt-1 space-y-1 text-sm">{plan.constraints.map((c, i) => <li key={`${c.kind}-${i}`}><Badge variant="outline">{c.kind === "allow" ? "允许" : c.kind === "deny" ? "禁止" : "规则"}</Badge> <span className="text-xs text-muted-foreground">{c.origin}</span> · {c.text}</li>)}</ul> : <p className="mt-1 text-sm text-muted-foreground">没有登记的任务约束。</p>}</div>
      <div><h4 className="text-sm font-medium">继承材料（{plan.materials.length}）</h4>{plan.materials.length ? <ul className="mt-1 space-y-1 text-sm">{plan.materials.map((m) => <li key={m.id}>{m.name} · {m.size_bytes.toLocaleString()} B</li>)}</ul> : <p className="mt-1 text-sm text-muted-foreground">没有登记的主任务材料。</p>}{plan.materials.length > 0 && <details className="mt-1 text-xs text-muted-foreground"><summary className="cursor-pointer py-1">查看材料 SHA-256</summary><ul>{plan.materials.map((m) => <li key={m.id} className="break-all">{m.name} · {m.sha256}</li>)}</ul></details>}</div>
      <div><h4 className="text-sm font-medium">设备能力匹配（{plan.devices.length}）</h4>{plan.devices.length ? <div className="mt-2 grid gap-2 md:grid-cols-2">{plan.devices.map((d) => <article key={d.id} className="rounded-md border p-3 text-sm"><div className="flex flex-wrap items-center gap-2"><strong>{d.name}</strong><Badge variant="outline">设备 #{d.id}</Badge><span className="text-xs text-muted-foreground">成员 {d.member_name} · #{d.member_id}</span><Badge variant={d.matched && d.online ? "secondary" : "outline"}>{!d.online ? "离线" : d.matched ? "匹配" : "未匹配"}</Badge></div>{d.issues.map((issue, i) => <p key={i} className="mt-1 text-xs text-destructive">{explainIssue(issue)}</p>)}<ul className="mt-2 space-y-1">{d.roles.map((r) => <li key={r.key} className="border-t pt-1"><span className="font-medium">{roleLabel[r.key] ?? "协作角色"}</span> <Badge variant={r.ready ? "secondary" : "outline"}>{r.ready ? "就绪" : "未就绪"}</Badge>{r.issues.map((issue, i) => <p key={i} className="text-xs text-destructive">{explainIssue(issue)}</p>)}<details className="text-xs text-muted-foreground"><summary className="cursor-pointer py-1">查看已检测工具与角色编号</summary><p>角色编号：{r.key}</p><p>已检测工具：{r.capabilities.length ? r.capabilities.join("、") : "无"}</p></details></li>)}</ul></article>)}</div> : <p className="mt-1 text-sm text-muted-foreground">暂无设备信息。</p>}</div>
      {plan.warnings.length > 0 && <div className="rounded-md border p-3"><h4 className="text-sm font-medium">提示</h4><ul className="mt-1 list-disc pl-5 text-sm">{plan.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul></div>}
      {plan.blockers.length > 0 && <div role="alert" className="rounded-md border border-destructive/40 p-3"><h4 className="text-sm font-medium">暂不能启用</h4><ul className="mt-1 list-disc pl-5 text-sm">{plan.blockers.map((b, i) => <li key={i}>{b}</li>)}</ul></div>}
      <p className="text-xs text-muted-foreground">确认后保持暂停；点击“开始协作”后自动拆分、匹配空闲设备和分配资产。</p>
      <label className="flex min-h-10 items-center gap-2 text-sm"><input type="checkbox" checked={checked} disabled={busy || disabled || !plan.can_enable} onChange={(e) => setChecked(e.target.checked)} />我已核对目标范围、约束、材料、设备能力和自动派发设置。</label>
      <Button type="button" disabled={busy || disabled || !plan.can_enable || !checked} onClick={() => void enable()}>{busy ? "正在启用…" : "确认配置并启用协作"}</Button>
    </section>}
  </div>;
}
