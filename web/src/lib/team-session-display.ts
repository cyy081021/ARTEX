import type { TeamSession } from "@/lib/types";

export type TeamSessionFilter = "all" | "sendable" | "readonly";

export function teamSessionWorkerLabel(id: string): string {
  const intent = /^intent:(\d+)$/.exec(id);
  if (intent) return `Worker #${intent[1]}`;
  if (id.startsWith("main:")) return "主 Agent";
  if (id === "plan") return "Planner";
  return "共享会话";
}

export function teamSessionStateLabel(state: string): string {
  const labels: Record<string, string> = {
    idle: "空闲",
    running: "运行中",
    open: "待执行",
    paused: "已暂停",
    done: "已完成",
    readonly: "只读",
    completed: "已完成",
    stopped: "已停止",
    waiting: "等待中",
    pending: "等待中",
    queued: "排队中",
    blocked: "等待条件满足",
    exhausted: "额度已耗尽",
    failed: "执行失败",
    cancelled: "已取消",
    timeout: "已超时",
    finalizing: "收尾中",
  };
  return labels[state.toLowerCase()] ?? state;
}

export function visibleTeamSessions(sessions: TeamSession[], canSteer: boolean, filter: TeamSessionFilter) {
  const visible = sessions.filter((session) =>
    filter === "all" || ((canSteer && session.can_message) === (filter === "sendable")),
  );
  return visible.sort((a, b) => Number(!!(canSteer && b.can_message)) - Number(!!(canSteer && a.can_message)));
}

export function reconcileTeamSession(
  currentID: string,
  sessions: TeamSession[],
  canSteer: boolean,
  filter: TeamSessionFilter,
): string {
  if (currentID && sessions.some((session) => session.id === currentID)) return currentID;
  return visibleTeamSessions(sessions, canSteer, filter)[0]?.id ?? "";
}
