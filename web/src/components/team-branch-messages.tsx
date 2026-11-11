"use client";

import * as React from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ArrowUpIcon, Loader2Icon } from "lucide-react";
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupTextarea } from "@/components/ui/input-group";
import { ScrollArea } from "@/components/ui/scroll-area";
import { TaskSessionPanel } from "@/components/task-session-layout";
import { TeamMessageTranscript } from "@/components/team-message-transcript";
import type { Session, SessionStatus, TeamSessionMessage } from "@/lib/types";
import { TeamSessionWorkspace } from "@/components/team-shared-messages";
import { http } from "@/lib/api";
import { branchSnapshotRequests, projectBranchEvents } from "./team-branch-messages-state.mjs";

type Branch = {
  id: number;
  owner_id: number;
  control_id: number;
  device_id: number;
  state: string;
  review_mode?: "automatic" | "manual";
  review_reason?: string;
  spec: { title: string; question: string; coordinator?: boolean; kind: string };
  units: { id: number; state: string; result?: { summary: string; outcome: string } }[];
};
type Event = {
  id: number;
  branch_id: number;
  kind: string;
  text: string;
  member_id?: number;
  device_id?: number;
  created_at: string;
};
type Snapshot = {
  project: { state: string; branches: Branch[]; policy: { auto_dispatch?: boolean; auto_review?: boolean } };
  permissions: string[];
  events: Event[];
  cursor: number;
  has_more: boolean;
};

const visibleKinds = new Set(["plan", "message", "guidance", "submitted", "auto_review", "review_required", "review"]);
const branchStates: Record<string, string> = {
  waiting_ready: "等待设备",
  waiting_dependency: "等待依赖",
  running: "执行中",
  paused: "已暂停",
  review_pending: "待人工复审",
  accepted: "已接收",
  needs_supplement: "待补充",
  failed: "失败",
  cancelled: "已停止",
};
function requestID() {
  return globalThis.crypto?.randomUUID?.() ?? `branch-guide-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}
function statusCode(error: unknown) {
  return (error as { status?: number } | null)?.status;
}
function preferredBranch(branches: Branch[]) {
  return [...branches].sort((a, b) => Number(!!b.spec.coordinator) - Number(!!a.spec.coordinator) || b.id - a.id)[0];
}

export function TeamBranchMessages({
  team,
  taskId,
  memberID,
  admin,
}: {
  team: string;
  taskId: string;
  memberID: number;
  admin: boolean;
}) {
  const base = `/teams/${encodeURIComponent(team)}/tasks/${encodeURIComponent(taskId)}/branches`;
  const scope = `${team}:${taskId}`;
  const scopeRef = React.useRef(scope);
  const cursorByBranch = React.useRef(new Map<number, number>());
  const eventCache = React.useRef(new Map<number, Event[]>());
  const [snapshot, setSnapshot] = React.useState<Snapshot | null>(null);
  const [selected, setSelected] = React.useState(0);
  const [events, setEvents] = React.useState<Event[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [notice, setNotice] = React.useState("");
  const [fallback, setFallback] = React.useState(false);
  const [guide, setGuide] = React.useState("");
  const [refresh, bump] = React.useReducer((value: number) => value + 1, 0);
  const branches = snapshot?.project.branches ?? [];
  const branch = branches.find((item) => item.id === selected) ?? preferredBranch(branches);
  const canGuide =
    !!branch &&
    snapshot?.permissions.includes("guide") === true &&
    (admin || (branch.control_id === memberID && memberID > 0));
  const activeForGuidance =
    !!branch && ["running", "waiting_ready", "waiting_dependency", "paused"].includes(branch.state);

  React.useEffect(() => {
    scopeRef.current = scope;
    cursorByBranch.current.clear();
    eventCache.current.clear();
    setSnapshot(null);
    setEvents([]);
    setSelected(0);
    setError("");
    setNotice("");
    setFallback(false);
    setLoading(true);
  }, [scope]);

  React.useEffect(() => {
    if (fallback) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const requestedScope = scope;
    const load = async () => {
      try {
        const head = await http<Snapshot>(`${base}?after=0&limit=1`);
        if (!alive || scopeRef.current !== requestedScope) return;
        const nextBranches = head.project?.branches ?? [];
        setSnapshot(head);
        const allowedBranchIDs = new Set(nextBranches.map((item) => item.id));
        for (const branchID of eventCache.current.keys())
          if (!allowedBranchIDs.has(branchID)) eventCache.current.delete(branchID);
        for (const branchID of cursorByBranch.current.keys())
          if (!allowedBranchIDs.has(branchID)) cursorByBranch.current.delete(branchID);
        if (!head.permissions.includes("process")) {
          eventCache.current.clear();
          cursorByBranch.current.clear();
          setEvents([]);
          setError("");
          return;
        }
        if (!nextBranches.length) {
          setEvents([]);
          setError("");
          return;
        }
        if (!selected || !nextBranches.some((item) => item.id === selected)) {
          setSelected(preferredBranch(nextBranches)?.id ?? 0);
          setEvents([]);
          return;
        }
        const initialCursor = cursorByBranch.current.get(selected) ?? 0;
        const requests = branchSnapshotRequests(base, selected, initialCursor, head.permissions);
        if (!requests.events) {
          eventCache.current.clear();
          cursorByBranch.current.clear();
          setEvents([]);
          return;
        }
        let page = await http<Snapshot>(requests.events);
        const collected: Event[] = [];
        let safety = 0;
        let cursor = initialCursor;
        while (alive && scopeRef.current === requestedScope) {
          collected.push(...(page.events ?? []));
          const nextCursor = page.cursor ?? 0;
          if (!page.has_more || nextCursor <= cursor || ++safety >= 1000) {
            cursor = Math.max(cursor, nextCursor);
            break;
          }
          cursor = nextCursor;
          const nextRequests = branchSnapshotRequests(base, selected, cursor, head.permissions);
          if (!nextRequests.events) break;
          page = await http<Snapshot>(nextRequests.events);
        }
        if (!alive || scopeRef.current !== requestedScope) return;
        cursorByBranch.current.set(selected, cursor);
        const merged = projectBranchEvents(
          eventCache.current.get(selected) ?? [],
          collected,
          selected,
          visibleKinds,
          head.permissions,
        );
        eventCache.current.set(selected, merged);
        setEvents(merged);
        setError("");
      } catch (e) {
        if (!alive || scopeRef.current !== requestedScope) return;
        if (statusCode(e) === 404) {
          eventCache.current.clear();
          cursorByBranch.current.clear();
          setFallback(true);
          setSnapshot(null);
          setEvents([]);
        } else if (statusCode(e) === 401 || statusCode(e) === 403) {
          eventCache.current.clear();
          cursorByBranch.current.clear();
          setEvents([]);
          setSnapshot(null);
          setError(statusCode(e) === 403 ? "过程权限已收回；当前仅显示只读分支状态。" : "当前账号无权查看分支消息。");
        } else setError(`分支消息读取失败：${(e as Error).message}`);
      } finally {
        if (alive && scopeRef.current === requestedScope) {
          setLoading(false);
          timer = setTimeout(load, 2500);
        }
      }
    };
    setLoading(true);
    void load();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [base, scope, selected, refresh, fallback]);

  async function sendGuide(event: React.FormEvent) {
    event.preventDefault();
    const text = guide.trim();
    if (!branch || !canGuide || !activeForGuidance || !text || busy) return;
    const requestedScope = scope;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await http(`${base}/command`, {
        method: "POST",
        body: JSON.stringify({ type: "guide", request_id: requestID(), branch_id: branch.id, text }),
      });
      if (scopeRef.current !== requestedScope) return;
      setGuide("");
      setNotice("指导已记录；执行端会在下一工具边界应用提示。实际效果待后续状态确认。");
      bump();
    } catch (e) {
      if (scopeRef.current !== requestedScope) return;
      if (statusCode(e) === 403) {
        setError("当前账号无权发送此分支指导。");
      } else setError(`指导未发送：${(e as Error).message}`);
    } finally {
      if (scopeRef.current === requestedScope) setBusy(false);
    }
  }

  const states: Record<string, SessionStatus> = {
    waiting_ready: "pending",
    waiting_dependency: "pending",
    running: "running",
    paused: "paused",
    review_pending: "pending",
    accepted: "done",
    needs_supplement: "blocked",
    failed: "blocked",
    cancelled: "stopped",
  };
  const extraSessions: Session[] = branches.map((item) => ({
    id: `branch:${item.id}`,
    role: "worker",
    title: `${item.spec.coordinator ? "协调器 · " : ""}${item.spec.title}`,
    status: states[item.state] ?? "pending",
    live: item.state === "running",
    last_activity: "",
    intent_id: `B${item.id}`,
  }));
  const metadata = Object.fromEntries(
    branches.map((item) => [
      `branch:${item.id}`,
      { executorBadge: item.device_id ? `设备 #${item.device_id}` : "待分配" },
    ]),
  );
  const results = branch?.units.filter((unit) => unit.result?.summary) ?? [];
  const transcript: TeamSessionMessage[] = [
    ...events.map(
      (item): TeamSessionMessage => ({
        id: item.id,
        kind: item.kind === "guidance" ? "user" : "text",
        text: item.text,
        created_at: item.created_at,
        member_id: item.member_id ?? 0,
        executor_id: item.device_id ?? 0,
      }),
    ),
    ...results.map(
      (unit): TeamSessionMessage => ({
        id: -unit.id,
        kind: "text",
        text: `**工作结果摘要 · 工作单 #${unit.id}**\n\n${unit.result?.summary ?? ""}`,
        created_at: "",
        member_id: 0,
        executor_id: branch?.device_id ?? 0,
      }),
    ),
  ];
  return (
    <>
      {error && !snapshot && !fallback && (
        <div className="mb-3 flex items-center gap-2 text-sm text-destructive" role="alert">
          {error}
          <Button variant="outline" size="sm" disabled={loading} onClick={bump}>
            重新读取
          </Button>
        </div>
      )}
      <TeamSessionWorkspace
        team={team}
        taskId={taskId}
        extraSessions={fallback ? [] : extraSessions}
        extraMetadata={metadata}
        onSelectExtra={(id) => {
          const next = Number(id.slice(7));
          setSelected(next);
          setEvents(eventCache.current.get(next) ?? []);
          setGuide("");
          setNotice("");
        }}
        renderExtra={() => (
          <TaskSessionPanel
            header={
              <>
                <span className="min-w-0 truncate text-sm font-medium">{branch?.spec.title ?? "分支会话"}</span>
                {branch && <Badge variant="outline">分支 #{branch.id}</Badge>}
                <span className="ml-auto text-xs text-muted-foreground">
                  {branchStates[branch?.state ?? ""] ?? "等待状态"} ·{" "}
                  {canGuide && activeForGuidance ? "可交互" : "只读"}
                </span>
              </>
            }
          >
            <ScrollArea type="auto" className="min-h-0 min-w-0 flex-1 [&_[data-slot=scroll-area-viewport]>div]:block!">
              <div className="min-w-0 max-w-full p-4" aria-live="polite">
                {branch?.spec.question && <p className="mb-3 text-xs text-muted-foreground">{branch.spec.question}</p>}
                {branch?.review_reason && (
                  <p className="mb-3 text-xs text-muted-foreground">核验说明：{branch.review_reason}</p>
                )}
                {snapshot && !snapshot.permissions.includes("process") && (
                  <p className="text-xs text-muted-foreground">当前为只读视图，分支过程消息不可见。</p>
                )}
                {loading && !events.length && <p className="text-xs text-muted-foreground">正在读取分支消息…</p>}
                <TeamMessageTranscript messages={transcript} />
                {!loading && !transcript.length && (
                  <p className="text-xs text-muted-foreground">暂无可显示的计划、讨论或结果摘要。</p>
                )}
              </div>
            </ScrollArea>
            {error && (
              <p role="alert" className="px-4 py-2 text-xs text-destructive">
                {error}
              </p>
            )}
            {notice && (
              <p role="status" className="px-4 py-2 text-xs text-muted-foreground">
                {notice}
              </p>
            )}
            {canGuide && activeForGuidance ? (
              <form className="border-t p-3" onSubmit={(event) => void sendGuide(event)}>
                <InputGroup className="min-h-9 has-disabled:opacity-100">
                  <InputGroupTextarea
                    aria-label="发送执行指导"
                    value={guide}
                    onChange={(event) => setGuide(event.target.value)}
                    maxLength={4096}
                    rows={1}
                    disabled={busy}
                    placeholder="指导会在执行端下一工具边界应用"
                    className="max-h-36 min-h-9 overflow-y-auto"
                    onKeyDown={(event) => {
                      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
                        event.preventDefault();
                        void sendGuide(event);
                      }
                    }}
                  />
                  <InputGroupAddon align="block-end">
                    <span className="px-1 text-[10px] text-muted-foreground">Ctrl/⌘ + Enter 发送</span>
                    <InputGroupButton
                      type="submit"
                      variant="default"
                      className="ml-auto"
                      size="icon-xs"
                      aria-label="发送执行指导"
                      disabled={busy || !guide.trim()}
                    >
                      {busy ? <Loader2Icon className="animate-spin" /> : <ArrowUpIcon />}
                    </InputGroupButton>
                  </InputGroupAddon>
                </InputGroup>
              </form>
            ) : (
              <div className="border-t px-4 py-2 text-xs text-muted-foreground">
                {!canGuide ? "当前账号没有此分支的指导权限。" : "当前分支状态不接受新指导。"}
              </div>
            )}
          </TaskSessionPanel>
        )}
      />
    </>
  );
}
