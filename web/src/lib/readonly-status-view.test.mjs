import assert from "node:assert/strict";
import test from "node:test";

import { selectOfflineRecord, applyOfflineSnapshot } from "./readonly-status-view.ts";
import { t7StatusContent, t7StatusFromDetail } from "./status.ts";

function sample(budget) {
  return t7StatusFromDetail(200, { campaign: { remaining_budget_ms: budget } });
}

test("switching A to B to A ignores both earlier selections, even when their samples arrive last", async () => {
  let current = selectOfflineRecord("A", true);
  const firstA = current.pending;
  const lateA = Promise.withResolvers();
  const completion = lateA.promise.then(() => {
    current = applyOfflineSnapshot(current, firstA, sample(99), [{ reason: "旧 A" }]);
  });

  current = selectOfflineRecord("B", true);
  const b = current.pending;
  current = applyOfflineSnapshot(current, b, sample(22), [{ reason: "B 记录" }]);
  assert.equal(current.history[0].reason, "B 记录");

  current = selectOfflineRecord("A", true);
  const newA = current.pending;
  assert.notEqual(newA, firstA);
  assert.deepEqual(current.snapshot, { kind: "loading" });
  assert.equal(current.history, undefined);
  assert.equal(applyOfflineSnapshot(current, firstA, sample(99)), current);

  const accepted = applyOfflineSnapshot(current, newA, sample(0), [{ reason: "新 A" }]);
  current = accepted;
  lateA.resolve();
  await completion;
  assert.equal(current, accepted);
  assert.equal(applyOfflineSnapshot(current, b, { kind: "error" }), accepted);
  assert.equal(current.snapshot.campaign.remaining_budget_ms, 0);
  assert.deepEqual(current.history, [{ reason: "新 A" }]);
});

test("revocation and reselection of the same record invalidate an outstanding sample", () => {
  const initial = selectOfflineRecord("A", true);
  const first = initial.pending;
  const visible = applyOfflineSnapshot(initial, first, sample(10), [{ reason: "原可见记录" }]);
  const revoked = selectOfflineRecord("A", false);
  assert.deepEqual(revoked, { pending: null, snapshot: { kind: "forbidden" } });
  assert.equal(applyOfflineSnapshot(revoked, first, visible.snapshot, visible.history), revoked);
  const restored = selectOfflineRecord("A", true);
  assert.equal(restored.history, undefined);
  assert.deepEqual(restored.snapshot, { kind: "loading" });
  assert.equal(applyOfflineSnapshot(restored, first, visible.snapshot, visible.history), restored);

  const received = applyOfflineSnapshot(restored, restored.pending, sample(2), [{ reason: "重新可见" }]);
  assert.deepEqual(received.history, [{ reason: "重新可见" }]);
  assert.equal(applyOfflineSnapshot(received, first, { kind: "forbidden" }), received);
});

test("empty selection and non-ready snapshots omit history; a consumed selection cannot publish twice", () => {
  const initial = selectOfflineRecord("A", true);
  const selected = initial.pending;
  const history = [{ reason: "示例记录" }];
  const empty = selectOfflineRecord(null, true);
  assert.deepEqual(empty, { pending: null, snapshot: { kind: "unselected" } });
  assert.equal(t7StatusContent(empty.snapshot), "尚未选择记录");
  assert.equal(t7StatusContent(t7StatusFromDetail(404)), "暂无状态快照");
  assert.equal(applyOfflineSnapshot(empty, selected, sample(1), history), empty);
  assert.equal(applyOfflineSnapshot(initial, null, sample(1), history), initial);
  assert.equal(applyOfflineSnapshot(initial, selected, { kind: "loading" }, history), initial);
  for (const code of [401, 403, 404, 409, 500]) {
    const snapshot = t7StatusFromDetail(code);
    const rejected = applyOfflineSnapshot(initial, selected, snapshot, history);
    assert.deepEqual(rejected, { pending: null, snapshot });
    assert.equal(applyOfflineSnapshot(rejected, selected, sample(1), history), rejected);
  }
});

test("incomplete review entries keep their positions without exposing other fields", () => {
  const view = selectOfflineRecord("fixture", true);
  const history = [
    { reason: "第一条示例" },
    { reason: " \t\n ", action: "fixture-extra" },
    null,
    { reason: { detail: "fixture-extra" } },
    { action: "fixture-extra" },
    { reason: "最后一条示例", detail: "fixture-extra" },
  ];
  const result = applyOfflineSnapshot(view, view.pending, sample(0), history);
  assert.deepEqual(result.history, [
    { reason: "第一条示例" },
    { reason: "未提供原因" },
    { reason: "未提供原因" },
    { reason: "未提供原因" },
    { reason: "未提供原因" },
    { reason: "最后一条示例" },
  ]);
  assert.deepEqual(applyOfflineSnapshot(view, view.pending, sample(0), []).history, []);
  for (const missing of [undefined, null, { reason: "fixture-extra" }]) {
    assert.equal(applyOfflineSnapshot(view, view.pending, sample(0), missing).history, undefined);
  }
});
