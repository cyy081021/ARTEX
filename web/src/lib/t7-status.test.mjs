import assert from "node:assert/strict";
import test from "node:test";

import { t7Example, t7StatusContent } from "./status.ts";

const ready = {
  ...t7Example,
  campaign: {
    ...t7Example.campaign,
    total_budget_ms: 500,
    charged_budget_ms: 0,
    remaining_budget_ms: 350,
  },
  evidenceAvailable: true,
};

test("shows only the approved status fields and the supplied budgets", () => {
  assert.equal(t7Example.current_attempt.phase, "cleanup");
  const rows = t7StatusContent({
    ...ready,
    observed_execs: 12,
    latest_evidence: { id: 7, sha256: "fixture-only" },
    current_attempt: { ...ready.current_attempt, internal_note: "fixture-only" },
  });

  assert.deepEqual(rows, [
    ["当前状态", "停止中"],
    ["期望状态", "已请求暂停"],
    ["总预算", "500 ms"],
    ["已计入预算", "0 ms"],
    ["剩余预算", "350 ms"],
    ["清理状态", "待处理"],
    ["当前尝试阶段", "清理中"],
    ["尝试清理状态", "待处理"],
    ["资源保留", "已保留"],
    ["证据", "可用"],
  ]);
});

test("distinguishes unreported fields from zero budgets and negative indicators", () => {
  const missing = t7StatusContent({ kind: "ready", campaign: {}, current_attempt: {} });
  assert.deepEqual(missing, [
    ["当前状态", "未提供"],
    ["期望状态", "未提供"],
    ["总预算", "未提供"],
    ["已计入预算", "未提供"],
    ["剩余预算", "未提供"],
    ["清理状态", "未提供"],
    ["当前尝试阶段", "未提供"],
    ["尝试清理状态", "未提供"],
    ["资源保留", "未提供"],
    ["证据", "未提供"],
  ]);

  const reported = new Map(t7StatusContent({
    ...ready,
    campaign: { ...ready.campaign, total_budget_ms: 0, remaining_budget_ms: 0 },
    evidenceAvailable: false,
  }));
  assert.equal(reported.get("总预算"), "0 ms");
  assert.equal(reported.get("剩余预算"), "0 ms");
  assert.equal(reported.get("资源保留"), "已保留");
  assert.equal(reported.get("证据"), "暂无");
});

test("an interrupted snapshot distinguishes a hold and unknown status from missing data", () => {
  const rows = new Map(t7StatusContent({
    kind: "ready",
    campaign: {
      state: "interrupted",
      desired_state: "none",
      cleanup_status: "unknown",
      total_budget_ms: null,
      charged_budget_ms: 0,
    },
    current_attempt: { phase: "unrecognized-phase", resource_hold: true },
  }));

  assert.equal(rows.get("当前状态"), "已中断");
  assert.equal(rows.get("期望状态"), "无请求");
  assert.equal(rows.get("清理状态"), "未确认");
  assert.equal(rows.get("当前尝试阶段"), "未知");
  assert.equal(rows.get("资源保留"), "已保留");
  assert.equal(rows.get("总预算"), "未提供");
  assert.equal(rows.get("已计入预算"), "0 ms");
  assert.equal(rows.get("剩余预算"), "未提供");
});

test("a snapshot without a current attempt omits its rows", () => {
  for (const current_attempt of [null, undefined]) {
    const rows = t7StatusContent({ ...ready, current_attempt });
    assert.deepEqual(rows.map(([label]) => label), [
      "当前状态", "期望状态", "总预算", "已计入预算", "剩余预算", "清理状态", "证据",
    ]);
  }
});

test("loading, empty and error states replace the preceding ready content", () => {
  const snapshots = [ready, { kind: "loading" }, { kind: "empty" }, { kind: "error" }];
  const [data, ...messages] = snapshots.map((snapshot) => t7StatusContent(snapshot));
  assert.ok(Array.isArray(data));
  assert.deepEqual(messages, ["正在读取示例状态…", "暂无状态快照", "无法显示状态快照"]);
});
