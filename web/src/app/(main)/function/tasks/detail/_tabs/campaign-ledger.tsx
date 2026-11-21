"use client";

import * as React from "react";

import { ActivityIcon, RefreshCwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useTaskView } from "@/lib/task-view-context";
import type { CampaignRow } from "@/lib/types";

import { CampaignRowItem } from "./campaign-detail";

/**
 * Native 模糊测试战役（campaign）台账：状态机、预算电荷、检查点与清理结论都是
 * 可审计事实，worker 的一次性 fuzz 结果看不到这些。只在存在战役时渲染。
 */
export function CampaignLedgerCard({ taskId }: { taskId: string }) {
  const { api } = useTaskView();
  const [rows, setRows] = React.useState<CampaignRow[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.taskCampaigns(taskId);
      setRows(data);
      setError("");
    } catch (err) {
      // A task without campaigns answers 404/empty; only real failures are surfaced.
      const message = (err as Error).message || "";
      setRows([]);
      setError(message.includes("not_found") ? "" : message);
    } finally {
      setLoading(false);
    }
  }, [api, taskId]);

  React.useEffect(() => {
    void load();
  }, [load]);

  if (rows.length === 0 && !error) return null;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <ActivityIcon className="size-4 text-primary" />
            模糊测试战役
            <span className="text-muted-foreground text-xs font-normal">{rows.length} 个</span>
          </CardTitle>
          <CardDescription>
            campaign 是一次性 fuzz 之上的持久化版本：预算电荷、检查点、清理结论都可核对；崩溃仍只是候选。
            展开任一战役可看它的尝试与检查点。
          </CardDescription>
        </div>
        <Button size="sm" variant="ghost" onClick={() => void load()} disabled={loading} aria-label="刷新战役">
          <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} />
        </Button>
      </CardHeader>
      <CardContent className="space-y-2">
        {error ? <p className="text-rose-600 dark:text-rose-400 text-xs">{error}</p> : null}
        {rows.map((row) => (
          <CampaignRowItem key={row.id} taskId={taskId} row={row} />
        ))}
      </CardContent>
    </Card>
  );
}
