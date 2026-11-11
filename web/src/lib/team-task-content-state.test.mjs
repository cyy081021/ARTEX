import assert from "node:assert/strict";
import test from "node:test";
import { acceptsTeamTaskResponse, matchesTeamTaskScope } from "./team-task-content-state.mjs";

test("a response from a previous task or section cannot replace current content", () => {
  assert.equal(acceptsTeamTaskResponse("4:12:graph", "4:13:graph", 8, 8), false);
  assert.equal(acceptsTeamTaskResponse("4:12:graph", "4:12:findings", 8, 8), false);
});

test("a newer request in the same scope wins over an older refresh", () => {
  assert.equal(acceptsTeamTaskResponse("4:12:findings:1", "4:12:findings:1", 10, 11), false);
  assert.equal(acceptsTeamTaskResponse("4:12:findings:1", "4:12:findings:1", 11, 11), true);
});

test("old content is hidden immediately when the current scope changes", () => {
  assert.equal(matchesTeamTaskScope("4:12:findings:1:", "4:12:findings:1:q"), false);
  assert.equal(matchesTeamTaskScope("", "4:12:findings:1:"), false);
  assert.equal(matchesTeamTaskScope("4:12:findings:1:", "4:12:findings:1:"), true);
});
