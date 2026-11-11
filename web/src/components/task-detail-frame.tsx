"use client";

import * as React from "react";
import Link from "next/link";
import { ArrowLeftIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";

export const TASK_DETAIL_TABS = [
  { value: "sessions", label: "会话" }, { value: "overview", label: "总览" },
  { value: "graph", label: "探索链路" }, { value: "broadcast", label: "播报板" },
  { value: "findings", label: "发现" }, { value: "finding-relations", label: "漏洞关联" },
  { value: "retests", label: "复测" }, { value: "assets", label: "测试资产" },
  { value: "coverage", label: "资产覆盖图" }, { value: "intercept", label: "拦截审批" },
  { value: "report", label: "报告" }, { value: "workflow-requests", label: "跨流程协助" },
];

export function taskDetailTabs(kind?: string) {
  return kind === "reverse"
    ? [...TASK_DETAIL_TABS.filter((t) => !["findings", "finding-relations", "retests", "assets", "coverage", "intercept", "report"].includes(t.value)), { value: "reverse", label: "分析档案" }]
    : TASK_DETAIL_TABS;
}

// Both the owner and member workspace use this exact header and tab shell.
export function TaskDetailFrame({ task, tab, onTabChange, backHref, tabs, actions, interceptPendingCount = 0, children }: {
  task: {id: string | number; name?: string; description?: string; goal: string};
  tab: string; onTabChange: (value: string) => void; backHref: string;
  tabs: {value: string; label: string}[]; actions?: React.ReactNode;
  interceptPendingCount?: number; children: React.ReactNode;
}) {
  return <Tabs value={tab} onValueChange={onTabChange} className="flex flex-1 flex-col gap-0">
    <header className="sticky top-0 z-10 flex flex-col gap-2 border-b bg-background/95 px-4 py-2.5 backdrop-blur lg:px-6">
      <div className="flex items-center gap-2">
        <SidebarTrigger className="-ml-1" />
        <Button asChild variant="ghost" size="icon" className="size-7"><Link href={backHref} aria-label="返回任务列表"><ArrowLeftIcon /></Link></Button>
        <h1 className="min-w-0 flex-1 truncate text-sm font-semibold" title={task.name || task.description}>{task.name || task.description || `任务 ${task.id}`}</h1>
        <code className="hidden rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground sm:inline">{task.id}</code>
        <Separator orientation="vertical" className="mx-1 hidden h-4 sm:block" />
        {actions}
      </div>
      <p className="truncate text-xs text-muted-foreground">{task.goal}</p>
      <div className="no-scrollbar min-w-0 overflow-x-auto"><TabsList variant="default" className="min-w-max">
        {tabs.map((t) => <TabsTrigger key={t.value} value={t.value}>{t.label}{t.value === "intercept" && interceptPendingCount > 0 && <span className="ml-1.5 inline-flex h-4 min-w-[16px] items-center justify-center rounded-full bg-amber-500 px-1 text-[10px] font-semibold leading-none text-white">{interceptPendingCount > 99 ? "99+" : interceptPendingCount}</span>}</TabsTrigger>)}
      </TabsList></div>
    </header>
    {children}
  </Tabs>;
}
