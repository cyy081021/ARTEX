"use client";

import * as React from "react";
import { ArrowUpIcon, ClockIcon, Loader2Icon, RotateCwIcon, WifiOffIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupTextarea } from "@/components/ui/input-group";
import { ScrollArea } from "@/components/ui/scroll-area";
import { TooltipProvider } from "@/components/ui/tooltip";
import { TeamMessageTranscript } from "@/components/team-message-transcript";
import { SessionSidebar, TaskSessionLayout, TaskSessionPanel, TokenMetrics } from "@/components/task-session-layout";
import { api, createAPI, http } from "@/lib/api";
import type {
  Session,
  SessionStatus,
  SessionTokenUsage,
  TaskLLMResolution,
  TaskLLMResolutions,
  TeamSession,
  TeamSessionMessage,
  TokenTotal,
} from "@/lib/types";

const PAGE_SIZE = 100;

function nativeSession(item: TeamSession): Session {
  const worker = item.id.startsWith("intent:");
  const states: Record<string, SessionStatus> = {
    open: "pending",
    idle: "done",
    readonly: "done",
    failed: "blocked",
    cancelled: "stopped",
  };
  return {
    id: item.id,
    title: item.title,
    role: worker ? "worker" : item.id === "plan" ? "planner" : item.id === "system" ? "system" : "mainagent",
    status: states[item.state] ?? (item.state as SessionStatus),
    live: item.state === "running",
    last_activity: "",
    ...(worker ? { intent_id: item.id.slice(7) } : {}),
  };
}

function mergeMessages(current: TeamSessionMessage[], incoming: TeamSessionMessage[]) {
  const byID = new Map(current.map((message) => [message.id, message]));
  for (const message of incoming) byID.set(message.id, message);
  return [...byID.values()].sort((a, b) => a.id - b.id);
}

function newRequestID() {
  return globalThis.crypto?.randomUUID?.() ?? `team-message-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

// Extra execution branches use the same compact worker rows and transcript pane.
export function TeamSessionWorkspace({
  team,
  taskId,
  extraSessions = [],
  extraMetadata = {},
  renderExtra,
  onSelectExtra,
}: {
  team: string;
  taskId: string;
  extraSessions?: Session[];
  extraMetadata?: Record<string, { executorBadge?: string; displayTitle?: string }>;
  renderExtra?: (id: string) => React.ReactNode;
  onSelectExtra?: (id: string) => void;
}) {
  const [sessions, setSessions] = React.useState<TeamSession[]>([]);
  const [canSteer, setCanSteer] = React.useState(false);
  const [sessionID, setSessionID] = React.useState("");
  const [listOpen, setListOpen] = React.useState(false);
  const [error, setError] = React.useState("");
  const [messageError, setMessageError] = React.useState("");
  const [lastSynced, setLastSynced] = React.useState(0);
  const [retry, refresh] = React.useReducer((n: number) => n + 1, 0);
  const [tokens, setTokens] = React.useState<{ total: TokenTotal; sessions: SessionTokenUsage[] } | null>(null);
  const [resolutions, setResolutions] = React.useState<TaskLLMResolutions | null>(null);
  const [taskKind, setTaskKind] = React.useState("");
  const nativeAPI = React.useMemo(
    () =>
      createAPI(<T,>(path: string) =>
        http<T>(
          `/teams/${encodeURIComponent(team)}/tasks/${encodeURIComponent(taskId)}/native?${new URLSearchParams({ path })}`,
        ),
      ),
    [team, taskId],
  );
  React.useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const load = async () => {
      try {
        const result = await api.teamSessions(team, taskId);
        if (!alive) return;
        setSessions(result.sessions ?? []);
        setCanSteer(result.canSteer);
        setLastSynced(Date.now());
        setError("");
      } catch (e) {
        if (!alive) return;
        setError((e as Error).message);
        setCanSteer(false);
        if ([401, 403, 404].includes((e as { status: number }).status)) {
          setSessions([]);
          setSessionID("");
          setTokens(null);
          setResolutions(null);
        }
      } finally {
        if (alive) timer = setTimeout(load, 5000);
      }
    };
    void load();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [team, taskId, retry]);
  React.useEffect(() => {
    setSessions([]);
    setTokens(null);
    setResolutions(null);
    setSessionID("");
    setLastSynced(0);
    setMessageError("");
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const load = async () => {
      const results = await Promise.allSettled([
        nativeAPI.tokenStats(taskId),
        nativeAPI.taskLLMResolution(taskId),
        nativeAPI.task(taskId),
      ]);
      if (!alive) return;
      if (results[0].status === "fulfilled") setTokens(results[0].value);
      else setTokens(null);
      if (results[1].status === "fulfilled") setResolutions(results[1].value);
      else setResolutions(null);
      if (results[2].status === "fulfilled") setTaskKind(results[2].value.kind ?? "pentest");
      timer = setTimeout(load, 10000);
    };
    void load();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [nativeAPI, taskId]);
  const nativeSessions = [...sessions.map(nativeSession), ...extraSessions];
  const activeID = nativeSessions.some((item) => item.id === sessionID) ? sessionID : (nativeSessions[0]?.id ?? "");
  const session = sessions.find((item) => item.id === activeID);
  const active = nativeSessions.find((item) => item.id === activeID);
  const metadata = Object.fromEntries(
    sessions.map((item) => [
      item.id,
      {
        executorBadge: item.id.startsWith("intent:")
          ? item.executor_id === 0
            ? "本机"
            : `设备 #${item.executor_id}`
          : undefined,
      },
    ]),
  );
  const resolution =
    !session || session.id === "system"
      ? undefined
      : session.id.startsWith("main:")
        ? taskKind === "reverse"
          ? resolutions?.reverse_main
          : resolutions?.mainagent
        : session.id === "plan"
          ? taskKind === "reverse"
            ? resolutions?.reverse_planner
            : resolutions?.planner
          : taskKind === "reverse"
            ? undefined
            : resolutions?.worker;
  const healthy = lastSynced > 0 && !error && !messageError;
  return (
    <TooltipProvider delayDuration={300}>
      <TaskSessionLayout listOpen={listOpen} onListOpenChange={setListOpen}>
        <SessionSidebar
          sessions={nativeSessions}
          activeId={activeID}
          activeDisplayTitle={active?.title ?? ""}
          listOpen={listOpen}
          onListOpenChange={setListOpen}
          taskTokens={tokens?.total}
          metadata={{ ...metadata, ...extraMetadata }}
          headerSlot={
            <button
              type="button"
              onClick={refresh}
              className={`inline-flex items-center gap-1 text-[10px] ${healthy ? "text-emerald-500" : "text-amber-500"}`}
              title={error || messageError || "共享消息每 2 秒同步，会话列表每 5 秒同步；点击刷新"}
              aria-live="polite"
            >
              {healthy ? (
                <span className="size-1 animate-pulse rounded-full bg-emerald-500" />
              ) : (
                <WifiOffIcon className="size-3" />
              )}
              {healthy ? "实时" : error || messageError ? "重试中" : "连接中"}
            </button>
          }
          onSelect={(item) => {
            setSessionID(item.id);
            setListOpen(false);
            setMessageError("");
            if (extraSessions.some((extra) => extra.id === item.id)) onSelectExtra?.(item.id);
          }}
        />
        {session ? (
          <TeamSessionMessages
            key={`${team}:${taskId}:${session.id}`}
            team={team}
            taskId={taskId}
            session={session}
            canSteer={canSteer}
            panel
            tokens={tokens?.sessions.find((item) => item.session === session.id)}
            resolution={resolution}
            onSyncError={setMessageError}
            listError={error}
          />
        ) : active ? (
          renderExtra?.(active.id)
        ) : (
          <TaskSessionPanel header={<span className="text-sm font-medium">任务会话</span>}>
            <p className="p-4 text-sm text-muted-foreground">{error || "当前任务还没有可查看的会话。"}</p>
          </TaskSessionPanel>
        )}
      </TaskSessionLayout>
    </TooltipProvider>
  );
}

export function TeamSessionMessages({
  team,
  taskId,
  session,
  canSteer = true,
  panel = false,
  tokens,
  resolution,
  onSyncError,
  listError,
}: {
  team: string;
  taskId: string;
  session: TeamSession;
  canSteer?: boolean;
  panel?: boolean;
  tokens?: SessionTokenUsage;
  resolution?: TaskLLMResolution;
  onSyncError?: (error: string) => void;
  listError?: string;
}) {
  const [messages, setMessages] = React.useState<TeamSessionMessage[]>([]);
  const [hasMore, setHasMore] = React.useState(false);
  const [loadingOlder, setLoadingOlder] = React.useState(false);
  const [loading, setLoading] = React.useState(true);
  const [loadError, setLoadError] = React.useState("");
  const [sendError, setSendError] = React.useState("");
  const [draft, setDraft] = React.useState("");
  const [requestID, setRequestID] = React.useState("");
  const [sending, setSending] = React.useState(false);
  const [notice, setNotice] = React.useState("");
  const requestScope = React.useRef(0);
  const activeStreamKey = React.useRef("");
  const latestCursor = React.useRef(0);
  const messageScroller = React.useRef<HTMLDivElement>(null);
  const followLatest = React.useRef(true);
  const restoreScroll = React.useRef<{ height: number; top: number; follow: boolean } | null>(null);
  const sessionID = session.id;
  const assignmentID = session.assignment_id;
  const epoch = session.epoch;
  const streamKey = `${team}:${taskId}:${sessionID}:${assignmentID}:${epoch}`;

  React.useEffect(() => {
    const scope = ++requestScope.current;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    let hasLoadedSnapshot = false;
    const reset = () => {
      setMessages([]);
      setHasMore(false);
      setLoadingOlder(false);
      setLoading(true);
      setLoadError("");
      setSendError("");
      setDraft("");
      setRequestID("");
      setSending(false);
      setNotice("");
      latestCursor.current = 0;
      followLatest.current = true;
      restoreScroll.current = null;
    };
    if (activeStreamKey.current !== streamKey) {
      activeStreamKey.current = streamKey;
      reset();
    }
    const loadLatest = async () => {
      try {
        if (!hasLoadedSnapshot) {
          const page = await api.teamSessionMessages(team, taskId, sessionID, 0, PAGE_SIZE);
          if (!alive || scope !== requestScope.current) return;
          setMessages((current) => mergeMessages(current, page.items));
          setHasMore(page.hasMore);
          latestCursor.current = page.items.at(-1)?.id ?? 0;
          hasLoadedSnapshot = true;
        } else {
          const afterCursor = latestCursor.current;
          // Refresh the newest page so pending/delivered guidance states can advance.
          const latest = await api.teamSessionMessages(team, taskId, sessionID, 0, PAGE_SIZE);
          if (!alive || scope !== requestScope.current) return;
          setMessages((current) => mergeMessages(current, latest.items));

          // Recover every message missed while offline, even when the gap is larger
          // than one page. `after` is ascending and has_more means another page exists.
          let cursor = afterCursor;
          let page = await api.teamSessionMessagesAfter(team, taskId, sessionID, cursor, PAGE_SIZE);
          while (alive && scope === requestScope.current) {
            if (page.items.length) {
              setMessages((current) => mergeMessages(current, page.items));
              cursor = Math.max(cursor, page.items.at(-1)?.id ?? cursor);
            }
            if (!page.hasMore || !page.items.length || cursor <= afterCursor) break;
            page = await api.teamSessionMessagesAfter(team, taskId, sessionID, cursor, PAGE_SIZE);
          }
          if (alive && scope === requestScope.current) latestCursor.current = Math.max(latestCursor.current, cursor);
        }
        if (!alive || scope !== requestScope.current) return;
        setLoadError("");
        onSyncError?.("");
      } catch (e) {
        if (alive && scope === requestScope.current) {
          setLoadError((e as Error).message);
          onSyncError?.((e as Error).message);
          if ([401, 403, 404].includes((e as { status: number }).status)) {
            setMessages([]);
            setHasMore(false);
          }
        }
      } finally {
        if (alive && scope === requestScope.current) {
          setLoading(false);
          timer = setTimeout(loadLatest, 2000);
        }
      }
    };
    void loadLatest();
    return () => {
      alive = false;
      clearTimeout(timer);
      requestScope.current += 1;
    };
  }, [team, taskId, sessionID, streamKey, onSyncError]);

  React.useLayoutEffect(() => {
    const element = messageScroller.current;
    if (!element) return;
    const hasMessages = messages.length > 0;
    const restore = restoreScroll.current;
    if (restore) {
      element.scrollTop = restore.top + element.scrollHeight - restore.height;
      followLatest.current = restore.follow;
      restoreScroll.current = null;
    } else if (followLatest.current && hasMessages) {
      element.scrollTop = element.scrollHeight;
    }
  }, [messages]);

  async function loadOlder() {
    if (loadingOlder || !hasMore || !messages.length) return;
    const scope = requestScope.current;
    setLoadingOlder(true);
    try {
      const page = await api.teamSessionMessages(team, taskId, sessionID, messages[0].id, PAGE_SIZE);
      if (scope !== requestScope.current) return;
      const element = messageScroller.current;
      if (element) {
        restoreScroll.current = {
          height: element.scrollHeight,
          top: element.scrollTop,
          follow: followLatest.current,
        };
      }
      setMessages((current) => {
        return mergeMessages(page.items, current);
      });
      setHasMore(page.hasMore);
    } catch (e) {
      if (scope === requestScope.current) setLoadError((e as Error).message);
    } finally {
      if (scope === requestScope.current) setLoadingOlder(false);
    }
  }

  async function send() {
    const message = draft.trim();
    if (!message || !canSend || sending || Array.from(message).length > 4000) return;
    const id = requestID || newRequestID();
    const scope = requestScope.current;
    if (!requestID) setRequestID(id);
    setSending(true);
    setNotice("");
    try {
      const intentID = Number(session.id.startsWith("intent:") ? session.id.slice(7) : 0);
      const result = await api.sendTeamSessionMessage(team, taskId, {
        intent_id: intentID,
        assignment_id: assignmentID,
        epoch,
        request_id: id,
        message,
      });
      if (scope !== requestScope.current) return;
      setDraft("");
      setRequestID("");
      setSendError("");
      followLatest.current = true;
      const element = messageScroller.current;
      if (element) element.scrollTop = element.scrollHeight;
      setNotice(
        result.status === "steering"
          ? "消息已交付执行端，实际执行效果待后续消息确认。"
          : "消息已接受，等待交付到执行端。",
      );
    } catch (e) {
      // Keep both the draft and request ID so retry remains idempotent.
      if (scope !== requestScope.current) return;
      setSendError(`发送失败，可重试：${(e as Error).message}`);
    } finally {
      if (scope === requestScope.current) setSending(false);
    }
  }

  const canSend = canSteer && session.can_message;
  const reason = !canSteer
    ? "当前账号没有任务执行权限，因此共享会话均为只读。"
    : (session.reason ?? "此会话当前不可发送引导。");
  const first = messages[0]?.created_at;
  const last = messages.at(-1)?.created_at;
  const duration = first && last ? Math.max(0, Math.floor((Date.parse(last) - Date.parse(first)) / 60000)) : 0;
  const header = (
    <>
      <span className="min-w-0 truncate text-sm font-medium">
        {sessionID.startsWith("intent:") ? "Worker 执行会话" : session.title}
      </span>
      {resolution && (
        <Badge variant="outline" className="max-w-28 shrink-0 font-normal" title={resolution.model}>
          {resolution.available ? resolution.name || resolution.model : "模型不可用"}
        </Badge>
      )}
      {sessionID.startsWith("intent:") && (
        <Badge variant="secondary">{session.executor_id === 0 ? "本机" : `设备 #${session.executor_id}`}</Badge>
      )}
      {hasMore && (
        <button
          type="button"
          className="text-[10px] text-muted-foreground"
          disabled={loadingOlder}
          onClick={() => void loadOlder()}
        >
          ↑ 更早历史
        </button>
      )}
      <div className="ml-auto flex min-w-0 max-w-full items-center justify-end gap-x-3 gap-y-1 text-xs text-muted-foreground max-sm:w-full max-sm:flex-wrap">
        {tokens && (
          <>
            <TokenMetrics
              input={tokens.input_tokens}
              cache={tokens.cache_read_tokens}
              output={tokens.output_tokens}
              labels="long"
              className="max-sm:hidden"
            />
            <TokenMetrics
              input={tokens.input_tokens}
              cache={tokens.cache_read_tokens}
              output={tokens.output_tokens}
              className="sm:hidden"
            />
          </>
        )}
        {duration > 0 && (
          <span className="inline-flex items-center gap-1" title="已加载消息的起止时长">
            <ClockIcon className="size-3" />
            {duration >= 60 ? `${Math.floor(duration / 60)}h${duration % 60}m` : `${duration}m`}
          </span>
        )}
        <span title={canSend ? "引导会在执行边界应用" : reason}>{canSend ? "可交互" : "只读"}</span>
      </div>
    </>
  );
  const body = (
    <>
      <ScrollArea
        type="auto"
        className="min-h-0 min-w-0 flex-1 [&_[data-slot=scroll-area-viewport]>div]:block!"
        ref={(root) => {
          messageScroller.current = root?.querySelector<HTMLDivElement>('[data-slot="scroll-area-viewport"]') ?? null;
        }}
        onScrollCapture={(event) => {
          const element = event.target as HTMLDivElement;
          if (element !== messageScroller.current) return;
          followLatest.current = element.scrollHeight - element.scrollTop - element.clientHeight <= 32;
          if (element.scrollTop < 40 && hasMore && !loadingOlder) void loadOlder();
        }}
      >
        <div className="min-w-0 max-w-full p-4" aria-live="polite">
          {hasMore && (
            <Button type="button" variant="ghost" size="sm" disabled={loadingOlder} onClick={() => void loadOlder()}>
              {loadingOlder ? <Loader2Icon className="animate-spin" /> : <RotateCwIcon />}加载更早消息
            </Button>
          )}
          {loading && !messages.length && <p className="text-xs text-muted-foreground">正在读取消息…</p>}
          {!loading && !messages.length && <p className="text-xs text-muted-foreground">还没有共享消息。</p>}
          <TeamMessageTranscript messages={messages} />
        </div>
      </ScrollArea>
      {(listError || loadError || sendError) && (
        <p role="alert" className="px-4 py-2 text-xs text-destructive">
          {listError || loadError || sendError}
        </p>
      )}
      {notice && (
        <p role="status" className="px-4 py-2 text-xs text-muted-foreground">
          {notice}
        </p>
      )}
      {canSend ? (
        <div className="border-t p-3">
          <InputGroup className="min-h-9 has-disabled:opacity-100">
            <InputGroupTextarea
              aria-label="发送共享会话消息"
              placeholder="输入消息，调整执行方向…"
              value={draft}
              onChange={(event) => {
                if (event.target.value !== draft) {
                  setRequestID("");
                  setSendError("");
                }
                setDraft(event.target.value);
                setNotice("");
              }}
              onKeyDown={(event) => {
                if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
                  event.preventDefault();
                  void send();
                }
              }}
              disabled={sending}
              rows={1}
              className="max-h-36 min-h-9 overflow-y-auto"
            />
            <InputGroupAddon align="block-end">
              <span className="px-1 text-[10px] text-muted-foreground">
                {Array.from(draft).length}/4000 · Ctrl/⌘ + Enter
              </span>
              <InputGroupButton
                className="ml-auto"
                size="icon-xs"
                variant="default"
                aria-label="发送消息"
                title="发送消息"
                disabled={sending || !draft.trim() || Array.from(draft).length > 4000}
                onClick={() => void send()}
              >
                {sending ? <Loader2Icon className="animate-spin" /> : <ArrowUpIcon />}
              </InputGroupButton>
            </InputGroupAddon>
          </InputGroup>
        </div>
      ) : (
        <div className="border-t px-4 py-2 text-xs text-muted-foreground">{reason}</div>
      )}
    </>
  );
  return panel ? (
    <TaskSessionPanel header={header}>{body}</TaskSessionPanel>
  ) : (
    <div className="flex h-[32rem] min-w-0 flex-col">
      {header}
      {body}
    </div>
  );
}
