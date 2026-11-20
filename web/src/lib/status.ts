// Centralised status → color/label semantics, reused across the whole app.
// Spec §8.3: 意图 / 覆盖 / 任务 / 严重度 each have a consistent color set.

export type Tone = "neutral" | "blue" | "green" | "amber" | "red" | "rose" | "violet" | "slate";

export const toneClasses: Record<Tone, string> = {
  neutral: "bg-muted text-muted-foreground border-transparent",
  blue: "bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/20",
  green: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/20",
  amber: "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/20",
  red: "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/20",
  // rose 用作「严重」——实心高强调,视觉上明显高于「高危」的软红描边。
  rose: "bg-rose-600 text-white border-rose-600 dark:bg-rose-600 dark:text-white",
  violet: "bg-violet-500/15 text-violet-600 dark:text-violet-400 border-violet-500/20",
  slate: "bg-slate-500/15 text-slate-600 dark:text-slate-400 border-slate-500/20",
};

export const toneDot: Record<Tone, string> = {
  neutral: "bg-muted-foreground",
  blue: "bg-blue-500",
  green: "bg-emerald-500",
  amber: "bg-amber-500",
  red: "bg-red-500",
  rose: "bg-white",
  violet: "bg-violet-500",
  slate: "bg-slate-500",
};

interface StatusMeta {
  label: string;
  tone: Tone;
}

const intent: Record<string, StatusMeta> = {
  open: { label: "待领", tone: "slate" },
  waiting: { label: "等待前置", tone: "amber" },
  running: { label: "执行中", tone: "blue" },
  paused: { label: "已暂停", tone: "amber" },
  done: { label: "已完成", tone: "green" },
  // blocked = 模型/API/网络故障重试用尽，这条意图基本没真正探成（非目标拦截）。
  blocked: { label: "执行受阻", tone: "red" },
  // exhausted = 达到步数/时间预算被中途掐断、只写回部分结果（非方向已探尽）。
  exhausted: { label: "预算耗尽", tone: "violet" },
  // stopped = 历史软删除状态（保留,历史数据）。
  stopped: { label: "已停止", tone: "slate" },
  // deleted = 用户假删除了该意图（保留节点与血缘，删除原因见 delete_reason 字段）。
  deleted: { label: "已删除", tone: "slate" },
};

const task: Record<string, StatusMeta> = {
  finalizing: { label: "收尾中", tone: "blue" },
  created: { label: "已创建", tone: "slate" },
  queued: { label: "排队中", tone: "amber" },
  running: { label: "运行中", tone: "blue" },
  paused: { label: "已暂停", tone: "amber" },
  done: { label: "已完成", tone: "green" },
  failed: { label: "失败", tone: "red" },
  timeout: { label: "已超时", tone: "amber" },
};

const severity: Record<string, StatusMeta> = {
  critical: { label: "严重", tone: "rose" },
  high: { label: "高危", tone: "red" },
  medium: { label: "中危", tone: "amber" },
  low: { label: "低危", tone: "slate" },
};

const finding: Record<string, StatusMeta> = {
  pending: { label: "待处理", tone: "amber" },
  in_progress: { label: "处理中", tone: "blue" },
  confirmed: { label: "已确认", tone: "red" },
  resolved: { label: "已处理", tone: "green" },
  fixed: { label: "已修复", tone: "green" },
  false_positive: { label: "误报", tone: "slate" },
  ignored: { label: "忽略", tone: "neutral" },
  duplicate: { label: "重复", tone: "neutral" },
  risk_accepted: { label: "风险接受", tone: "violet" },
};

const engine: Record<string, StatusMeta> = {
  exploring: { label: "探索中", tone: "blue" },
  paused: { label: "已暂停", tone: "amber" },
  stalled: { label: "停滞", tone: "red" },
  idle: { label: "空闲", tone: "neutral" },
};

const goal: Record<string, StatusMeta> = {
  open: { label: "进行中", tone: "blue" },
  met: { label: "已达成", tone: "green" },
  abandoned: { label: "已放弃", tone: "slate" },
};

const audit: Record<string, StatusMeta> = {
  allow: { label: "放行", tone: "green" },
  block: { label: "拦截", tone: "red" },
};

const node: Record<string, StatusMeta> = {
  observed: { label: "观测", tone: "slate" },
  confirmed: { label: "确认", tone: "green" },
  tombstoned: { label: "废弃", tone: "neutral" },
};

// 推送投递状态。sending 用 blue 而不是 amber：它不是「有问题」，
// 而是「已被领取、正在发」，与 pending 的等待语义要能区分开。
const delivery: Record<string, StatusMeta> = {
  pending: { label: "待发送", tone: "amber" },
  sending: { label: "发送中", tone: "blue" },
  sent: { label: "已送达", tone: "green" },
  failed: { label: "失败", tone: "red" },
  skipped: { label: "已跳过", tone: "neutral" },
};

const maps = {
  intent,
  task,
  severity,
  finding,
  engine,
  goal,
  audit,
  node,
  delivery,
} as const;

export type StatusDomain = keyof typeof maps;

export function statusMeta(domain: StatusDomain, key: string): StatusMeta {
  return maps[domain][key] ?? { label: key, tone: "neutral" };
}

export type T7StatusSnapshot =
  | { kind: "loading" | "empty" | "error" | "unauthenticated" | "forbidden" | "unavailable" }
  | {
      kind: "ready";
      campaign: {
        state?: string | null;
        desired_state?: string | null;
        total_budget_ms?: number | null;
        charged_budget_ms?: number | null;
        remaining_budget_ms?: number | null;
        cleanup_status?: string | null;
      };
      current_attempt?: { phase?: string | null; cleanup_status?: string | null; resource_hold?: boolean | null } | null;
      // Only availability is carried into the view.
      evidenceAvailable?: boolean | null;
    };

const campaignStates = {
  draft: "草稿",
  queued: "排队中",
  running: "运行中",
  stopping: "停止中",
  paused: "已暂停",
  completed: "已完成",
  failed: "失败",
  cancelled: "已取消",
  interrupted: "已中断",
};

const requestedStates = {
  none: "无请求",
  queued: "已请求排队",
  running: "已请求运行",
  paused: "已请求暂停",
  cancelled: "已请求取消",
};

const attemptPhases = {
  preflight: "前置检查",
  startup: "启动中",
  tool_probe: "工具检查",
  instrumentation_probe: "插桩检查",
  campaign: "运行中",
  pause_collect: "暂停收集",
  checkpoint_write: "写入检查点",
  cleanup: "清理中",
  evidence: "证据整理",
  finalize: "收尾中",
};

const cleanupStatuses = {
  pending: "待处理",
  verified: "已验证",
  not_required: "无需清理",
  unknown: "未确认",
  failed: "失败",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function statusKey(value: unknown, labels: Record<string, string>) {
  if (typeof value !== "string" || !value) return undefined;
  return Object.hasOwn(labels, value) ? value : "unrecognized";
}

function isBudget(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

// Projects a detail response into display fields. The caller supplies the response.
export function t7StatusFromDetail(status: number | "loading", body?: unknown): T7StatusSnapshot {
  switch (status) {
    case "loading": return { kind: "loading" };
    case 401: return { kind: "unauthenticated" };
    case 403: return { kind: "forbidden" };
    case 404: return { kind: "empty" };
    case 409: return { kind: "unavailable" };
    case 200: break;
    default: return { kind: "error" };
  }

  if (!isRecord(body) || !isRecord(body.campaign)) return { kind: "error" };
  const { campaign, current_attempt: attempt, latest_evidence: evidence } = body;
  if (attempt != null && !isRecord(attempt)) return { kind: "error" };

  return {
    kind: "ready",
    campaign: {
      state: statusKey(campaign.state, campaignStates),
      desired_state: statusKey(campaign.desired_state, requestedStates),
      cleanup_status: statusKey(campaign.cleanup_status, cleanupStatuses),
      total_budget_ms: isBudget(campaign.total_budget_ms) ? campaign.total_budget_ms : undefined,
      charged_budget_ms: isBudget(campaign.charged_budget_ms) ? campaign.charged_budget_ms : undefined,
      remaining_budget_ms: isBudget(campaign.remaining_budget_ms) ? campaign.remaining_budget_ms : undefined,
    },
    current_attempt: attempt == null ? undefined : {
      phase: statusKey(attempt.phase, attemptPhases),
      cleanup_status: statusKey(attempt.cleanup_status, cleanupStatuses),
      resource_hold: typeof attempt.resource_hold === "boolean" ? attempt.resource_hold : undefined,
    },
    evidenceAvailable: evidence === null ? false :
      isRecord(evidence) && evidence.authority === "candidate-only" ? true : undefined,
  };
}

export const t7Example = t7StatusFromDetail(200, {
  campaign: {
    state: "stopping",
    desired_state: "paused",
    total_budget_ms: 60_000,
    charged_budget_ms: 15_000,
    remaining_budget_ms: 45_000,
    cleanup_status: "pending",
  },
  current_attempt: { phase: "cleanup", cleanup_status: "pending", resource_hold: true },
  latest_evidence: null,
});

export function t7StatusContent(snapshot: T7StatusSnapshot): string | [string, string][] {
  if (snapshot.kind !== "ready") {
    return {
      loading: "正在读取示例状态…",
      empty: "暂无状态快照",
      error: "无法显示状态快照",
      unauthenticated: "请先登录以查看状态",
      forbidden: "无权查看状态",
      unavailable: "状态暂不可用",
    }[snapshot.kind];
  }

  const missing = "未提供";
  const label = (value: string | null | undefined, labels: Record<string, string>) => {
    if (!value) return missing;
    return Object.hasOwn(labels, value) ? labels[value] : "未知";
  };
  const budget = (value?: number | null) =>
    isBudget(value) ? `${value.toLocaleString("zh-CN")} ms` : missing;
  const { campaign, current_attempt: attempt, evidenceAvailable } = snapshot;
  const rows: [string, string][] = [
    ["当前状态", label(campaign.state, campaignStates)],
    ["期望状态", label(campaign.desired_state, requestedStates)],
    ["总预算", budget(campaign.total_budget_ms)],
    ["已计入预算", budget(campaign.charged_budget_ms)],
    ["剩余预算", budget(campaign.remaining_budget_ms)],
    ["清理状态", label(campaign.cleanup_status, cleanupStatuses)],
  ];
  if (attempt) {
    rows.push(
      ["当前尝试阶段", label(attempt.phase, attemptPhases)],
      ["尝试清理状态", label(attempt.cleanup_status, cleanupStatuses)],
      ["资源保留", attempt.resource_hold == null ? missing : attempt.resource_hold ? "已保留" : "未保留"],
    );
  }
  rows.push(["证据", evidenceAvailable == null ? missing : evidenceAvailable ? "可用" : "暂无"]);
  return rows;
}
