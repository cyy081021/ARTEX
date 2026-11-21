"use client";

import * as React from "react";

import { toast } from "sonner";
import { CopyIcon, FlagIcon, RefreshCwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useTaskView } from "@/lib/task-view-context";
import type { TaskFlag } from "@/lib/types";

function fmtTime(value?: string): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

/**
 * CTF 模式的 flag 台账。agent 用 submit_flag 记账，运维也可以手工补记：两条路径
 * 写同一张表、同一套去重规则，所以界面上看到的永远是权威的那一份。
 */
export function FlagLedgerCard({ taskId, mode }: { taskId: string; mode?: string }) {
  const { api, readOnly } = useTaskView();
  const [flags, setFlags] = React.useState<TaskFlag[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [value, setValue] = React.useState("");
  const [source, setSource] = React.useState("");
  const [note, setNote] = React.useState("");
  const [saving, setSaving] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.taskFlags(taskId);
      setFlags(data.flags);
    } catch (error) {
      toast.error(`读取 flag 台账失败：${(error as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, [api, taskId]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const isCTF = mode === "ctf";
  // 普通任务没有台账；没有 flag 也不占地方。手工补记入口只在 CTF 模式下出现。
  if (!isCTF && flags.length === 0) return null;

  async function submit() {
    const trimmed = value.trim();
    if (!trimmed) {
      toast.error("flag 不能为空");
      return;
    }
    setSaving(true);
    try {
      const res = await api.addTaskFlag(taskId, { flag: trimmed, source: source.trim(), note: note.trim() });
      if (res.duplicate) {
        toast.info(`该 flag 已记录过（台账 #${res.flag.id}）`);
      } else {
        toast.success(`已记录 flag #${res.flag.id}`);
      }
      setValue("");
      setSource("");
      setNote("");
      await load();
    } catch (error) {
      toast.error(`记录失败：${(error as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast.success("已复制");
    } catch {
      toast.error("复制失败，请手动选择文本");
    }
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <FlagIcon className="size-4 text-amber-500" />
            CTF Flag 台账
            <span className="text-muted-foreground text-xs font-normal">{flags.length} 个</span>
          </CardTitle>
          <CardDescription>
            agent 用 submit_flag 记账；同一 flag 重复提交只记为 duplicate，不覆盖首次来源。
          </CardDescription>
        </div>
        <Button size="sm" variant="ghost" onClick={() => void load()} disabled={loading} aria-label="刷新 flag 台账">
          <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} />
        </Button>
      </CardHeader>
      <CardContent className="space-y-3">
        {flags.length === 0 ? (
          <p className="text-muted-foreground text-sm">还没有捕获到 flag。</p>
        ) : (
          <ul className="space-y-2">
            {flags.map((flag) => (
              <li key={flag.id} className="bg-muted/40 rounded-md border p-2">
                <div className="flex items-start justify-between gap-2">
                  <code className="break-all font-mono text-sm">{flag.value}</code>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="shrink-0"
                    onClick={() => void copy(flag.value)}
                    aria-label={`复制 flag ${flag.value}`}
                  >
                    <CopyIcon className="size-4" />
                  </Button>
                </div>
                <div className="text-muted-foreground mt-1 space-y-0.5 text-xs">
                  <div>
                    #{flag.id} · {fmtTime(flag.created_at)}
                    {flag.intent_id ? ` · 意图 ${flag.intent_id}` : " · 人工记录"}
                    <span className="ml-2 font-mono">{flag.sha256.slice(0, 12)}</span>
                  </div>
                  {flag.source ? <div className="break-all">来源：{flag.source}</div> : null}
                  {flag.note ? <div className="break-all">说明：{flag.note}</div> : null}
                </div>
              </li>
            ))}
          </ul>
        )}

        {isCTF && !readOnly ? (
          <div className="space-y-2 border-t pt-3">
            <Input
              placeholder="flag{...}（按原文精确比较，大小写不同算不同 flag）"
              value={value}
              onChange={(event) => setValue(event.target.value)}
              aria-label="flag 原文"
            />
            <div className="flex flex-col gap-2 sm:flex-row">
              <Input
                placeholder="来源（请求/命令/响应片段）"
                value={source}
                onChange={(event) => setSource(event.target.value)}
                aria-label="flag 来源"
              />
              <Input
                placeholder="说明（可选）"
                value={note}
                onChange={(event) => setNote(event.target.value)}
                aria-label="flag 说明"
              />
              <Button size="sm" className="shrink-0" onClick={() => void submit()} disabled={saving}>
                {saving ? "记录中…" : "记录 flag"}
              </Button>
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
