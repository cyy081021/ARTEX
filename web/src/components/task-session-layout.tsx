"use client";

import * as React from "react";
import {
  BrainIcon,
  ChevronDownIcon,
  CircleCheckIcon,
  CircleSlashIcon,
  CircleXIcon,
  ClockIcon,
  HistoryIcon,
  Loader2Icon,
  PauseIcon,
  PlusIcon,
  RadioIcon,
  RotateCwIcon,
  ShieldAlertIcon,
  Trash2Icon,
  UserIcon,
  ZapOffIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { Session, SessionStatus, TokenTotal } from "@/lib/types";
import { cn } from "@/lib/utils";

export function TaskSessionLayout({
  children,
  listOpen,
  onListOpenChange,
}: {
  children: React.ReactNode;
  listOpen: boolean;
  onListOpenChange: (open: boolean) => void;
}) {
  return (
    <div
      className={cn(
        "grid h-[calc(100svh-10rem)] min-h-0 grid-cols-1 gap-4",
        listOpen ? "grid-rows-[minmax(0,40svh)_minmax(0,1fr)]" : "grid-rows-[auto_minmax(0,1fr)]",
        "lg:h-[calc(100svh-13rem)] lg:grid-cols-[18rem_1fr] lg:grid-rows-[minmax(0,1fr)]",
      )}
    >
      {children}
    </div>
  );
}

export function TaskSessionPanel({
  children,
  header,
  className,
}: {
  children: React.ReactNode;
  header?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex min-h-0 flex-1 min-w-0 flex-col overflow-hidden rounded-lg border bg-card", className)}>
      {header && (
        <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 border-b px-3 py-2 sm:px-4 sm:py-2.5">
          {header}
        </div>
      )}
      {children}
    </div>
  );
}

export const TokenMetrics = React.forwardRef<
  HTMLSpanElement,
  React.ComponentPropsWithoutRef<"span"> & { input: number; cache: number; output: number; labels?: "short" | "long" }
>(({ input, cache, output, labels = "short", className, ...props }, ref) => {
  const names = labels === "short" ? ["入", "缓", "出"] : ["input", "cache", "output"];
  return (
    <span
      ref={ref}
      className={cn("inline-flex min-w-0 flex-wrap items-center gap-1 text-muted-foreground", className)}
      {...props}
    >
      {[input, cache, output].map((value, index) => (
        <React.Fragment key={names[index]}>
          <span>{names[index]}</span>
          <Badge variant="secondary" className="h-5 px-1.5 font-mono tabular-nums">
            {value >= 1_000_000
              ? `${(value / 1_000_000).toFixed(value >= 10_000_000 ? 0 : 1)}M`
              : value >= 1000
                ? `${(value / 1000).toFixed(value >= 10000 ? 0 : 1)}k`
                : String(value)}
          </Badge>
        </React.Fragment>
      ))}
    </span>
  );
});
TokenMetrics.displayName = "TokenMetrics";

const roleMeta = {
  mainagent: { label: "主 Agent", icon: UserIcon },
  planner: { label: "规划 Planner", icon: BrainIcon },
  worker: { label: "Workers", icon: RadioIcon },
  system: { label: "系统审计", icon: HistoryIcon },
} as const;
function statusIcon(status: SessionStatus) {
  switch (status) {
    case "running":
      return <Loader2Icon className="size-3.5 animate-spin text-blue-500" />;
    case "paused":
      return <PauseIcon className="size-3.5 text-amber-500" />;
    case "pending":
      return <ClockIcon className="size-3.5 text-muted-foreground" />;
    case "done":
      return <CircleCheckIcon className="size-3.5 text-emerald-500" />;
    case "stopped":
      return <CircleSlashIcon className="size-3.5 text-amber-500" />;
    case "blocked":
      return <CircleXIcon className="size-3.5 text-red-500" />;
    case "exhausted":
      return <ZapOffIcon className="size-3.5 text-violet-500" />;
    case "deleted":
      return <CircleSlashIcon className="size-3.5 text-muted-foreground" />;
  }
}

export type SessionRowMetadata = {
  displayTitle?: string;
  hasPending?: boolean;
  unread?: number;
  deleted?: boolean;
  executorBadge?: string;
  controlling?: boolean;
};
function SessionItem({
  session: s,
  active,
  metadata: meta = {},
  onSelect,
  onCancel,
}: {
  session: Session;
  active: boolean;
  metadata?: SessionRowMetadata;
  onSelect: () => void;
  onCancel?: () => void;
}) {
  const icon = meta.deleted ? (
    <Trash2Icon className="size-3.5 text-destructive" />
  ) : s.role === "worker" ? (
    statusIcon(s.status)
  ) : s.live ? (
    <Loader2Icon className="size-3.5 animate-spin text-blue-500" />
  ) : null;
  const cancellable =
    !!onCancel &&
    s.role === "worker" &&
    !s.inherited &&
    !meta.deleted &&
    ["running", "paused", "pending"].includes(s.status);
  return (
    <div
      className={cn(
        "group/session flex w-full items-center rounded-md transition-colors",
        active ? "bg-accent text-accent-foreground" : "hover:bg-accent/50",
      )}
    >
      <button
        type="button"
        onClick={onSelect}
        className="flex min-w-0 flex-1 items-center gap-1 px-2 py-1.5 text-left text-sm"
      >
        {icon ?? <span className="size-3.5 shrink-0" />}
        {s.intent_id && (
          <span className="shrink-0 rounded bg-muted px-1 py-0.5 font-mono text-[10px] tabular-nums text-muted-foreground">
            #{s.intent_id}
          </span>
        )}
        {s.inherited && s.source_task_id && (
          <Badge variant="outline" className="shrink-0">
            来源 #{s.source_task_id}
          </Badge>
        )}
        {meta.executorBadge && (
          <Badge variant="secondary" className="h-5 shrink-0 px-1.5 font-mono text-[10px] tabular-nums">
            {meta.executorBadge}
          </Badge>
        )}
        <span
          className={cn(
            "min-w-0 flex-1 truncate text-sm font-medium",
            meta.deleted && "text-muted-foreground line-through",
          )}
        >
          {meta.displayTitle ?? s.title}
        </span>
        {meta.deleted && (
          <Badge variant="outline" className="shrink-0 border-destructive/40 text-destructive">
            已删除
          </Badge>
        )}
        {meta.hasPending && <ShieldAlertIcon className="size-3.5 shrink-0 text-amber-500" />}
        {!active && meta.unread ? (
          <span className="inline-flex min-w-4 items-center justify-center rounded-full bg-blue-500/15 px-1 text-[10px] font-medium tabular-nums text-blue-600 dark:text-blue-400">
            {meta.unread > 99 ? "99+" : meta.unread}
          </span>
        ) : null}
        {s.live && (
          <span className="inline-flex items-center gap-1 rounded bg-blue-500/15 px-1.5 py-0.5 text-[10px] font-medium text-blue-600 dark:text-blue-400">
            <span className="size-1 animate-pulse rounded-full bg-blue-500" />
            实时
          </span>
        )}
      </button>
      {cancellable && (
        <div className="flex shrink-0 items-center gap-0.5 pr-1 opacity-100 sm:opacity-0 sm:transition-opacity sm:group-hover/session:opacity-100 sm:group-focus-within/session:opacity-100">
          <Button
            type="button"
            variant="ghost"
            size="icon-xs"
            onClick={onCancel}
            disabled={meta.controlling}
            title="删除该意图（需填写原因，可选假删除/真删除）"
            aria-label="删除该意图（需填写原因，可选假删除/真删除）"
            className="text-destructive hover:text-destructive"
          >
            <Trash2Icon />
          </Button>
        </div>
      )}
    </div>
  );
}

export function SessionSidebar({
  sessions,
  activeId,
  activeDisplayTitle,
  hiddenUnread = 0,
  taskTokens,
  headerSlot,
  onSelect,
  onCreateMain,
  creatingMain = false,
  onCancel,
  metadata = {},
  hasMoreWorkers = false,
  loadingMoreWorkers = false,
  onLoadMoreWorkers,
  emptyWorkers = false,
  listOpen,
  onListOpenChange,
}: {
  sessions: Session[];
  activeId: string;
  activeDisplayTitle: string;
  hiddenUnread?: number;
  taskTokens?: TokenTotal | null;
  headerSlot?: React.ReactNode;
  onSelect: (session: Session) => void;
  onCreateMain?: () => void;
  creatingMain?: boolean;
  onCancel?: (session: Session) => void;
  metadata?: Record<string, SessionRowMetadata>;
  hasMoreWorkers?: boolean;
  loadingMoreWorkers?: boolean;
  onLoadMoreWorkers?: () => void;
  emptyWorkers?: boolean;
  listOpen: boolean;
  onListOpenChange: (open: boolean) => void;
}) {
  return (
    <div className="flex min-h-0 flex-col overflow-hidden rounded-lg border bg-card">
      <div className="border-b px-3 py-2">
        <div className="flex items-center justify-between gap-2">
          <button
            type="button"
            onClick={() => onListOpenChange(!listOpen)}
            aria-expanded={listOpen}
            aria-controls="session-list-panel"
            className="flex min-w-0 flex-1 items-center gap-1 text-left text-xs font-medium text-muted-foreground lg:pointer-events-none"
          >
            <ChevronDownIcon
              className={cn("size-3.5 shrink-0 transition-transform lg:hidden", !listOpen && "-rotate-90")}
            />
            <span className="shrink-0">会话列表</span>
            {!listOpen && (
              <>
                <span className="min-w-0 truncate text-foreground lg:hidden" title={activeDisplayTitle}>
                  · {activeDisplayTitle}
                </span>
                {hiddenUnread > 0 && (
                  <span className="inline-flex min-w-4 shrink-0 items-center justify-center rounded-full bg-blue-500/15 px-1 text-[10px] font-medium tabular-nums text-blue-600 lg:hidden dark:text-blue-400">
                    {hiddenUnread > 99 ? "99+" : hiddenUnread}
                  </span>
                )}
              </>
            )}
          </button>
          {headerSlot}
        </div>
        {taskTokens && (
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="mt-2 flex min-w-0 flex-wrap items-center gap-1 text-xs text-muted-foreground">
                <span>任务总计</span>
                <span>·</span>
                <TokenMetrics
                  input={taskTokens.input_tokens}
                  cache={taskTokens.cache_read_tokens}
                  output={taskTokens.output_tokens}
                />
              </div>
            </TooltipTrigger>
            <TooltipContent>
              输入 {taskTokens.input_tokens.toLocaleString()} · 输出 {taskTokens.output_tokens.toLocaleString()} ·
              缓存读取 {taskTokens.cache_read_tokens.toLocaleString()} · 缓存写入{" "}
              {taskTokens.cache_write_tokens.toLocaleString()}
            </TooltipContent>
          </Tooltip>
        )}
      </div>
      <ScrollArea
        id="session-list-panel"
        type="auto"
        className={cn("min-h-0 flex-1 [&_[data-slot=scroll-area-viewport]>div]:block!", !listOpen && "max-lg:hidden")}
      >
        <div className="flex w-full flex-col gap-3 p-2">
          {(["mainagent", "planner", "system", "worker"] as const).map((role) => {
            const items = sessions.filter((session) => session.role === role);
            if (!items.length) return null;
            const Meta = roleMeta[role];
            return (
              <div key={role} className="flex flex-col gap-0.5">
                <div className="flex items-center gap-1.5 px-2 py-1 text-xs font-medium text-muted-foreground">
                  <Meta.icon className="size-3.5" />
                  {Meta.label}
                  {role === "mainagent" && onCreateMain && (
                    <button
                      type="button"
                      onClick={onCreateMain}
                      disabled={creatingMain}
                      title="新建主 Agent 会话（清空上下文，任务状态保留）"
                      aria-label="新建主 Agent 会话"
                      className="ml-auto flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-muted-foreground hover:bg-accent/60 hover:text-foreground disabled:opacity-50"
                    >
                      {creatingMain ? (
                        <Loader2Icon className="size-3.5 animate-spin" />
                      ) : (
                        <PlusIcon className="size-3.5" />
                      )}
                      新建
                    </button>
                  )}
                </div>
                {items.map((session) => (
                  <SessionItem
                    key={session.id}
                    session={session}
                    active={session.id === activeId}
                    metadata={metadata[session.id]}
                    onSelect={() => onSelect(session)}
                    onCancel={onCancel ? () => onCancel(session) : undefined}
                  />
                ))}
                {role === "worker" && hasMoreWorkers && (
                  <button
                    type="button"
                    onClick={onLoadMoreWorkers}
                    disabled={loadingMoreWorkers}
                    className="mt-0.5 flex items-center justify-center gap-1 rounded-md px-2 py-1 text-xs text-muted-foreground hover:bg-accent/50"
                  >
                    {loadingMoreWorkers ? (
                      <Loader2Icon className="size-3.5 animate-spin" />
                    ) : (
                      <RotateCwIcon className="size-3.5" />
                    )}
                    加载更早的 Worker
                  </button>
                )}
              </div>
            );
          })}
          {emptyWorkers && !sessions.some((session) => session.role === "worker") && (
            <div className="px-2 py-1 text-xs text-muted-foreground">暂无运行中的 Worker 会话。</div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
