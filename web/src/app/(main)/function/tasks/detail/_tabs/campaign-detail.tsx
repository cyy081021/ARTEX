"use client";

import * as React from "react";

import { ChevronDownIcon, ChevronRightIcon, RefreshCwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { useTaskView } from "@/lib/task-view-context";
import type { CampaignAttemptRow, CampaignCheckpointRow, CampaignRow } from "@/lib/types";

function fmtDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "0s";
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return rest ? `${minutes}m${rest}s` : `${minutes}m`;
}

function stateTone(state: string): string {
  switch (state) {
    case "completed":
    case "persisted":
    case "verified":
      return "text-emerald-600 dark:text-emerald-400";
    case "running":
    case "launching":
    case "claimed":
      return "text-foreground";
    case "paused":
    case "stopping":
      return "text-amber-600 dark:text-amber-400";
    case "failed":
    case "interrupted":
    case "cancelled":
      return "text-rose-600 dark:text-rose-400";
    default:
      return "text-muted-foreground";
  }
}

function when(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString();
}

/**
 * 展开一次的尝试与检查点明细。数据按需拉取：战役列表可能很多，但只有展开的那一条需要
 * attempts / checkpoints 这两个更重的读。
 */
function CampaignDetail({ taskId, campaign }: { taskId: string; campaign: CampaignRow }) {
  const { api } = useTaskView();
  const [attempts, setAttempts] = React.useState<CampaignAttemptRow[]>([]);
  const [checkpoints, setCheckpoints] = React.useState<CampaignCheckpointRow[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [nextAttempts, nextCheckpoints] = await Promise.all([
        api.campaignAttempts(taskId, campaign.id),
        api.campaignCheckpoints(taskId, campaign.id),
      ]);
      setAttempts(nextAttempts);
      setCheckpoints(nextCheckpoints);
      setError("");
    } catch (err) {
      setError((err as Error).message || "读取战役明细失败");
    } finally {
      setLoading(false);
    }
  }, [api, campaign.id, taskId]);

  React.useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="mt-2 space-y-2 border-t pt-2">
      <div className="flex items-center justify-between">
        <span className="text-muted-foreground text-xs">
          尝试 {attempts.length} 次 · 检查点 {checkpoints.length} 个
        </span>
        <Button size="sm" variant="ghost" onClick={() => void load()} disabled={loading} aria-label="刷新明细">
          <RefreshCwIcon className={loading ? "size-3 animate-spin" : "size-3"} />
        </Button>
      </div>
      {error ? <p className="text-rose-600 dark:text-rose-400 text-xs">{error}</p> : null}
      {attempts.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-muted-foreground">
              <tr>
                <th className="py-1 pr-3 font-medium">#</th>
                <th className="py-1 pr-3 font-medium">状态</th>
                <th className="py-1 pr-3 font-medium">用时 / 预留</th>
                <th className="py-1 pr-3 font-medium">清理</th>
                <th className="py-1 pr-3 font-medium">槽位</th>
                <th className="py-1 pr-3 font-medium">检查点</th>
                <th className="py-1 pr-3 font-medium">结束原因</th>
                <th className="py-1 font-medium">时间</th>
              </tr>
            </thead>
            <tbody>
              {attempts.map((attempt) => (
                <tr key={attempt.id} className="border-t">
                  <td className="py-1 pr-3 font-mono">{attempt.attempt_no}</td>
                  <td className={`py-1 pr-3 font-medium ${stateTone(attempt.state)}`}>{attempt.state}</td>
                  <td className="py-1 pr-3">
                    {fmtDuration(attempt.actual_elapsed_ms)} / {fmtDuration(attempt.reserved_budget_ms)}
                    {attempt.budget_overrun ? <span className="text-rose-600 dark:text-rose-400"> 超预算</span> : null}
                  </td>
                  <td className="py-1 pr-3">{attempt.cleanup_status}</td>
                  <td className="py-1 pr-3">{attempt.resource_hold ? "占用中" : "已释放"}</td>
                  <td className="py-1 pr-3 font-mono">{attempt.checkpoint_id ?? "—"}</td>
                  <td className="py-1 pr-3">{attempt.termination_reason || "—"}</td>
                  <td className="text-muted-foreground py-1">{when(attempt.started_at || attempt.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {checkpoints.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-muted-foreground">
              <tr>
                <th className="py-1 pr-3 font-medium">检查点</th>
                <th className="py-1 pr-3 font-medium">尝试</th>
                <th className="py-1 pr-3 font-medium">状态</th>
                <th className="py-1 pr-3 font-medium">条目 / 字节</th>
                <th className="py-1 font-medium">时间</th>
              </tr>
            </thead>
            <tbody>
              {checkpoints.map((checkpoint) => (
                <tr key={checkpoint.id} className="border-t">
                  <td className="py-1 pr-3 font-mono">#{checkpoint.id}</td>
                  <td className="py-1 pr-3 font-mono">{checkpoint.attempt_id}</td>
                  <td className={`py-1 pr-3 ${stateTone(checkpoint.state)}`}>{checkpoint.state}</td>
                  <td className="py-1 pr-3">
                    {checkpoint.entry_count} / {checkpoint.total_bytes}B
                    {checkpoint.truncated ? <span className="text-amber-600 dark:text-amber-400"> 截断</span> : null}
                  </td>
                  <td className="text-muted-foreground py-1">{when(checkpoint.verified_at || checkpoint.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {!loading && !error && attempts.length === 0 && checkpoints.length === 0 ? (
        <p className="text-muted-foreground text-xs">还没有尝试或检查点。</p>
      ) : null}
    </div>
  );
}

/**
 * 战役台账的一行：可展开查看 attempts / checkpoints。状态机、预算电荷与清理结论都是可审计
 * 事实，worker 的一次性 fuzz 结果看不到这些。
 */
export function CampaignRowItem({ taskId, row }: { taskId: string; row: CampaignRow }) {
  const [open, setOpen] = React.useState(false);
  const pct = row.total_budget_ms > 0 ? Math.min(100, Math.round((row.charged_budget_ms / row.total_budget_ms) * 100)) : 0;
  const Chevron = open ? ChevronDownIcon : ChevronRightIcon;
  return (
    <div className="rounded-md border p-2 text-xs">
      <button
        type="button"
        className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 text-left"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        <Chevron className="size-3.5 shrink-0" />
        <span className="font-mono">#{row.id}</span>
        <span className={`font-medium ${stateTone(row.state)}`}>{row.state}</span>
        <span className="text-muted-foreground">v{row.state_version}</span>
        <span className="text-muted-foreground">
          预算 {fmtDuration(row.charged_budget_ms)} / {fmtDuration(row.total_budget_ms)}（{pct}%）
        </span>
        <span className="text-muted-foreground">清理 {row.cleanup_status}</span>
        {row.latest_checkpoint_id ? (
          <span className="text-muted-foreground">检查点 #{row.latest_checkpoint_id}</span>
        ) : null}
        {row.current_attempt_id ? <span className="text-muted-foreground">attempt #{row.current_attempt_id}</span> : null}
      </button>
      {open ? <CampaignDetail taskId={taskId} campaign={row} /> : null}
    </div>
  );
}
