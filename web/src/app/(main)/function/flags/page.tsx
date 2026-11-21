"use client";

import * as React from "react";

import Link from "next/link";

import { toast } from "sonner";
import { CopyIcon, FlagIcon, RefreshCwIcon, SearchIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { useTaskView } from "@/lib/task-view-context";
import type { TaskFlagRow } from "@/lib/types";

function fmtTime(value?: string): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

/**
 * 跨任务 flag 看板。比赛里每个题是一个任务，flag 分散在各任务台账里；这里把它们
 * 按任务聚到一起，方便一眼确认哪些题已经拿到 flag、哪些还没有。
 */
export default function FlagsPage() {
  const { api } = useTaskView();
  const [flags, setFlags] = React.useState<TaskFlagRow[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [query, setQuery] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.allFlags(500);
      setFlags(data.flags);
    } catch (error) {
      toast.error(`读取 flag 台账失败：${(error as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, [api]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const filtered = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return flags;
    return flags.filter((f) =>
      [f.value, f.task_name, f.source, f.note, String(f.task_id)].some((v) => (v ?? "").toLowerCase().includes(q)),
    );
  }, [flags, query]);

  const groups = React.useMemo(() => {
    const map = new Map<string, { taskId: number; taskName: string; rows: TaskFlagRow[] }>();
    for (const flag of filtered) {
      const key = String(flag.task_id);
      const entry = map.get(key) ?? { taskId: flag.task_id, taskName: flag.task_name || `#${flag.task_id}`, rows: [] };
      entry.rows.push(flag);
      map.set(key, entry);
    }
    return [...map.values()];
  }, [filtered]);

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast.success("已复制");
    } catch {
      toast.error("复制失败，请手动选择文本");
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <FlagIcon className="size-5 text-amber-500" /> Flag 台账
              <span className="text-muted-foreground text-sm font-normal">
                {flags.length} 个 / {groups.length} 个任务
              </span>
            </CardTitle>
            <CardDescription>
              CTF 模式任务捕获的 flag 汇总。agent 用 submit_flag 记账，运维可在任务详情里手工补记；同一 flag 重复提交只记一次。
            </CardDescription>
          </div>
          <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} /> 刷新
          </Button>
        </CardHeader>
        <CardContent>
          <div className="relative max-w-sm">
            <SearchIcon className="text-muted-foreground absolute top-2.5 left-2.5 size-4" />
            <Input
              className="pl-8"
              placeholder="搜索 flag / 任务名 / 来源"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
        </CardContent>
      </Card>

      {loading && flags.length === 0 ? (
        <div className="text-muted-foreground flex items-center gap-2 p-6 text-sm">
          <Spinner /> 正在读取…
        </div>
      ) : groups.length === 0 ? (
        <Card>
          <CardContent className="text-muted-foreground p-6 text-sm">
            还没有捕获到 flag。CTF 模式的任务在拿到 flag 时会自动记账；也可以在任务详情页手工补记。
          </CardContent>
        </Card>
      ) : (
        groups.map((group) => (
          <Card key={group.taskId}>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Link
                  href={`/function/tasks/detail?id=${encodeURIComponent(String(group.taskId))}`}
                  className="hover:underline"
                >
                  {group.taskName}
                </Link>
                <span className="text-muted-foreground font-mono text-xs">#{group.taskId}</span>
                <span className="text-muted-foreground text-xs font-normal">{group.rows.length} 个 flag</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {group.rows.map((flag) => (
                <div key={flag.id} className="bg-muted/40 rounded-md border p-2">
                  <div className="flex items-start justify-between gap-2">
                    <code className="break-all font-mono text-sm">{flag.value}</code>
                    <Button size="sm" variant="ghost" className="shrink-0" onClick={() => void copy(flag.value)}>
                      <CopyIcon className="size-4" />
                    </Button>
                  </div>
                  <div className="text-muted-foreground mt-1 space-y-0.5 text-xs">
                    <div>
                      {fmtTime(flag.created_at)} · {flag.intent_id ? `意图 ${flag.intent_id}` : "人工记录"}
                      <span className="ml-2 font-mono">{flag.sha256.slice(0, 12)}</span>
                    </div>
                    {flag.source ? <div className="break-all">来源：{flag.source}</div> : null}
                    {flag.note ? <div className="break-all">说明：{flag.note}</div> : null}
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        ))
      )}
    </div>
  );
}
