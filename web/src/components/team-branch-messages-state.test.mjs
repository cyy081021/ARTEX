import assert from "node:assert/strict";
import test from "node:test";
import { branchSnapshotRequests, projectBranchEvents } from "./team-branch-messages-state.mjs";

test("the branch catalog head stays unfiltered while event pages target one selected branch", () => {
  const requests = branchSnapshotRequests("/teams/2/tasks/8/branches", 31, 120, ["read", "process"]);
  assert.equal(requests.head, "/teams/2/tasks/8/branches?after=0&limit=1");
  assert.equal(new URL(requests.head, "http://localhost").searchParams.has("branch"), false);
  assert.equal(requests.events, "/teams/2/tasks/8/branches?after=120&limit=100&branch=31");
});

test("revoking process access clears cached events and prevents cursor pagination", () => {
  const requests = branchSnapshotRequests("/branches", 31, 120, ["read"]);
  assert.equal(requests.events, null);
  assert.deepEqual(projectBranchEvents([{ id: 1, branch_id: 31, kind: "message" }], [], 31, new Set(["message"]), ["read"]), []);
});

test("branch event projection filters other branches and deduplicates replayed IDs", () => {
  const visibleKinds = new Set(["message", "plan"]);
  const current = [{ id: 4, branch_id: 31, kind: "message", text: "old" }];
  const incoming = [
    { id: 4, branch_id: 31, kind: "message", text: "updated" },
    { id: 5, branch_id: 32, kind: "message", text: "other" },
    { id: 6, branch_id: 31, kind: "tool_start", text: "raw" },
    { id: 7, branch_id: 31, kind: "plan", text: "plan" },
  ];
  assert.deepEqual(projectBranchEvents(current, incoming, 31, visibleKinds, ["read", "process"]), [
    { id: 4, branch_id: 31, kind: "message", text: "updated" },
    { id: 7, branch_id: 31, kind: "plan", text: "plan" },
  ]);
});
