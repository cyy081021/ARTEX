import assert from "node:assert/strict";
import test from "node:test";
import type { TeamSession } from "./types";
import { reconcileTeamSession, teamSessionWorkerLabel, teamSessionStateLabel, visibleTeamSessions } from "./team-session-display";

const session = (id: string, can_message: boolean, executor_id = 0): TeamSession => ({
  id, title: "same title", state: can_message ? "running" : "done", can_message,
  executor_id, executor_name: "node", team_id: 4, assignment_id: 0, epoch: 0,
});

test("a fresh workspace selects a sendable Work without confusing its device number", () => {
  const items = [session("main:0", false), session("plan", false), session("intent:2469", true, 7)];
  assert.equal(reconcileTeamSession("", items, true, "all"), "intent:2469");
  assert.equal(teamSessionWorkerLabel(items[2].id), "Worker #2469");
  assert.equal(teamSessionStateLabel("open"), "待执行");
  assert.equal(reconcileTeamSession("", items, false, "sendable"), "");
});

test("polling preserves a selected conversation when its Work finishes", () => {
  const items = [session("intent:2469", false), session("intent:2470", true)];
  assert.equal(reconcileTeamSession("intent:2469", items, true, "sendable"), "intent:2469");
  assert.deepEqual(visibleTeamSessions(items, true, "sendable").map((v) => v.id), ["intent:2470"]);
});

test("an empty filtered list stays empty rather than selecting a read-only main session", () => {
  const items = [session("main:0", false), session("intent:2469", false)];
  assert.equal(reconcileTeamSession("", items, true, "sendable"), "");
  assert.equal(reconcileTeamSession("deleted", items, true, "sendable"), "");
  assert.equal(reconcileTeamSession("", [...items, session("intent:2470", true)], true, "sendable"), "intent:2470");
});

test("read-only permission removes sending choices and sorting preserves the source order", () => {
  const items = [session("main:0", false), session("intent:2469", true)];
  assert.equal(visibleTeamSessions(items, false, "sendable").length, 0);
  assert.equal(visibleTeamSessions(items, false, "readonly").length, 2);
  visibleTeamSessions(items, true, "all");
  assert.equal(items[0].id, "main:0");
});
