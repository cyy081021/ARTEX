import assert from "node:assert/strict";
import test from "node:test";

import { t7Example, t7StatusContent, t7StatusFromDetail } from "./status.ts";

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

test("projects detail fields and drops unrelated response data before rendering", (t) => {
  const fetch = t.mock.method(globalThis, "fetch", () => assert.fail("unexpected network request"));
  const marker = "must-stay-out-of-view";
  const detail = {
    campaign: {
      state: "stopping", desired_state: "paused", cleanup_status: "pending",
      total_budget_ms: 300, charged_budget_ms: 0, remaining_budget_ms: 75, last_error: marker,
    },
    current_attempt: { phase: "cleanup", resource_hold: true, lease_owner: marker },
    latest_evidence: { authority: "candidate-only", sha256: marker },
    events: [{ message: marker }], observed_execs: 21,
  };
  const projected = t7StatusFromDetail(200, detail);
  assert.deepEqual(projected, {
    kind: "ready",
    campaign: {
      state: "stopping", desired_state: "paused", cleanup_status: "pending",
      total_budget_ms: 300, charged_budget_ms: 0, remaining_budget_ms: 75,
    },
    current_attempt: { phase: "cleanup", cleanup_status: undefined, resource_hold: true },
    evidenceAvailable: true,
  });
  const rows = new Map(t7StatusContent(projected));
  assert.equal(rows.get("当前状态"), "停止中");
  assert.equal(rows.get("期望状态"), "已请求暂停");
  assert.equal(rows.get("剩余预算"), "75 ms");
  assert.equal(rows.get("已计入预算"), "0 ms");

  const paused = t7StatusFromDetail(200, {
    campaign: { state: "paused", remaining_budget_ms: 0 },
    current_attempt: { phase: marker, resource_hold: false }, latest_evidence: null,
  });
  assert.ok(!JSON.stringify(paused).includes(marker));
  const next = new Map(t7StatusContent(paused));
  assert.equal(next.get("当前状态"), "已暂停");
  assert.equal(next.get("期望状态"), "未提供");
  assert.equal(next.get("已计入预算"), "未提供");
  assert.equal(next.get("剩余预算"), "0 ms");
  assert.equal(next.get("资源保留"), "未保留");
  assert.equal(next.get("当前尝试阶段"), "未知");
  assert.equal(next.get("证据"), "暂无");
  assert.equal(fetch.mock.callCount(), 0);
});

test("loading and non-success results discard any previous or error payload", () => {
  const previous = { campaign: { state: "paused" }, detail: "private error" };
  for (const [status, message] of [
    ["loading", "正在读取示例状态…"], [401, "请先登录以查看状态"],
    [403, "无权查看状态"], [404, "暂无状态快照"],
    [409, "状态暂不可用"], [500, "无法显示状态快照"],
  ]) {
    const snapshot = t7StatusFromDetail(status, previous);
    assert.deepEqual(Object.keys(snapshot), ["kind"]);
    assert.equal(t7StatusContent(snapshot), message);
  }
});

test("handles absent or malformed detail without interpreting list rows as a detail", () => {
  for (const payload of [null, { campaigns: [] }, { campaign: [] }, { campaign: {}, current_attempt: true }]) {
    assert.deepEqual(t7StatusFromDetail(200, payload), { kind: "error" });
  }
  for (const evidence of [undefined, {}, "unexpected"]) {
    const rows = new Map(t7StatusContent(t7StatusFromDetail(200, {
      campaign: { remaining_budget_ms: "0" }, current_attempt: null, latest_evidence: evidence,
    })));
    assert.equal(rows.get("剩余预算"), "未提供");
    assert.equal(rows.get("证据"), "未提供");
    assert.ok(!rows.has("资源保留"));
  }
});
